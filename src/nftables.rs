use std::{
    cell::Cell,
    ffi::CStr,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    os::{
        fd::BorrowedFd,
        raw::{c_char, c_void},
    },
    rc::Rc,
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use mnl::mnl_sys;
use nftnl::{nftnl_sys, set::SetKey, Batch, FinalizedBatch, MsgType, NlMsg};

fn cidr_bound_ipv4(net: Ipv4Net) -> Option<Ipv4Addr> {
    let data = u32::from(net.network());
    let mask = u32::from(net.netmask());
    let ip = (!mask | data).wrapping_add(1);
    if ip == 0 {
        None
    } else {
        Some(ip.into())
    }
}

fn cidr_bound_ipv6(net: Ipv6Net) -> Option<Ipv6Addr> {
    let data = u128::from_be_bytes(net.network().octets());
    let mask = u128::from_be_bytes(net.netmask().octets());
    let ip = (!mask | data).wrapping_add(1);
    if ip == 0 {
        None
    } else {
        Some(ip.into())
    }
}

#[must_use]
struct FlushSetMsg<'a> {
    set: &'a Set1,
}
unsafe impl<'a> NlMsg for FlushSetMsg<'a> {
    unsafe fn write(&self, buf: *mut std::ffi::c_void, seq: u32, _msg_type: MsgType) {
        let header = nftnl_sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            libc::NFT_MSG_DELSETELEM as u16,
            self.set.family() as u16,
            0,
            seq,
        );
        nftnl_sys::nftnl_set_elems_nlmsg_build_payload(header, self.set.as_mut_ptr());
    }
}

pub struct SetElemsIter<'a> {
    set: &'a Set1,
    iter: *mut nftnl_sys::nftnl_set_elems_iter,
    ret: Rc<Cell<i32>>,
    is_first: bool,
}

impl<'a> SetElemsIter<'a> {
    fn new(set: &'a Set1) -> Self {
        let iter = unsafe { nftnl_sys::nftnl_set_elems_iter_create(set.as_mut_ptr()) };
        if iter.is_null() {
            panic!("oom");
        }
        SetElemsIter {
            set,
            iter,
            ret: Rc::new(Cell::new(1)),
            is_first: true,
        }
    }
}

impl<'a> Iterator for SetElemsIter<'a> {
    type Item = SetElemsMsg<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_first {
            self.is_first = false;
        } else {
            unsafe { nftnl_sys::nftnl_set_elems_iter_next(self.iter).is_null() };
        }
        if self.ret.get() <= 0
            || unsafe { nftnl_sys::nftnl_set_elems_iter_cur(self.iter).is_null() }
        {
            None
        } else {
            Some(SetElemsMsg {
                set: self.set,
                iter: self.iter,
                ret: self.ret.clone(),
            })
        }
    }
}

impl<'a> Drop for SetElemsIter<'a> {
    fn drop(&mut self) {
        unsafe { nftnl_sys::nftnl_set_elems_iter_destroy(self.iter) };
    }
}

pub struct SetElemsMsg<'a> {
    set: &'a Set1,
    iter: *mut nftnl_sys::nftnl_set_elems_iter,
    ret: Rc<Cell<i32>>,
}

unsafe impl<'a> NlMsg for SetElemsMsg<'a> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let (type_, flags) = match msg_type {
            MsgType::Add => (
                libc::NFT_MSG_NEWSETELEM,
                libc::NLM_F_CREATE | libc::NLM_F_EXCL,
            ),
            MsgType::Del => (libc::NFT_MSG_DELSETELEM, 0),
        };
        let header = nftnl_sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            type_ as u16,
            self.set.family() as u16,
            flags as u16,
            seq,
        );
        self.ret
            .set(nftnl_sys::nftnl_set_elems_nlmsg_build_payload_iter(
                header, self.iter,
            ));
    }
}

fn send_and_process(socket: &mnl::Socket, batch: &FinalizedBatch) -> io::Result<()> {
    socket.send_all(batch)?;
    let portid = socket.portid();
    let mut buf = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let fd = unsafe { mnl_sys::mnl_socket_get_fd(socket.as_raw_socket()) };
    let mut readfds = nix::sys::select::FdSet::new();
    let fd1 = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut tv = nix::sys::time::TimeVal::new(0, 0);
    loop {
        readfds.clear();
        readfds.insert(fd1);
        if nix::sys::select::select(fd + 1, &mut readfds, None, None, &mut tv)? <= 0 {
            break;
        }
        if !readfds.contains(fd1) {
            break;
        }
        let msglen = socket.recv(&mut buf)?;
        match mnl::cb_run(&buf[..msglen], 0, portid)? {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }
    Ok(())
}

pub struct Set1(*mut nftnl_sys::nftnl_set);
impl Set1 {
    pub fn new() -> Self {
        Self(unsafe { nftnl_sys::nftnl_set_alloc() })
    }
    pub fn as_mut_ptr(&self) -> *mut nftnl_sys::nftnl_set {
        self.0
    }
    pub fn table_name(&self) -> Option<&str> {
        let ret =
            unsafe { nftnl_sys::nftnl_set_get_str(self.0, nftnl_sys::NFTNL_SET_TABLE as u16) };
        (!ret.is_null())
            .then(|| unsafe { CStr::from_ptr(ret) }.to_str().ok())
            .flatten()
    }
    pub fn name(&self) -> Option<&str> {
        let ret = unsafe { nftnl_sys::nftnl_set_get_str(self.0, nftnl_sys::NFTNL_SET_NAME as u16) };
        (!ret.is_null())
            .then(|| unsafe { CStr::from_ptr(ret) }.to_str().ok())
            .flatten()
    }
    pub fn family(&self) -> u32 {
        unsafe { nftnl_sys::nftnl_set_get_u32(self.0, nftnl_sys::NFTNL_SET_FAMILY as u16) }
    }
    pub fn add_range<K: SetKey>(&mut self, lower: &K, excl_upper: Option<&K>) {
        let data1 = lower.data();
        let data1_len = data1.len() as u32;
        unsafe {
            let elem = nftnl_sys::nftnl_set_elem_alloc();
            if elem.is_null() {
                panic!("oom");
            }
            nftnl_sys::nftnl_set_elem_set(
                elem,
                nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                data1.as_ptr() as *const c_void,
                data1_len,
            );
            nftnl_sys::nftnl_set_elem_add(self.as_mut_ptr(), elem);

            let Some(data2) = excl_upper.map(|key| key.data()) else {
                return;
            };
            let data2_len = data2.len() as u32;

            let elem = nftnl_sys::nftnl_set_elem_alloc();
            if elem.is_null() {
                panic!("oom");
            }
            nftnl_sys::nftnl_set_elem_set(
                elem,
                nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                data2.as_ptr() as *const c_void,
                data2_len,
            );
            nftnl_sys::nftnl_set_elem_set_u32(
                elem,
                nftnl_sys::NFTNL_SET_ELEM_FLAGS as u16,
                libc::NFT_SET_ELEM_INTERVAL_END as u32,
            );
            nftnl_sys::nftnl_set_elem_add(self.as_mut_ptr(), elem);
        }
    }
    pub fn add_cidrs(
        &self,
        socket: &mnl::Socket,
        flush: bool,
        cidrs: impl IntoIterator<Item = IpNet>,
    ) -> io::Result<()> {
        let mut batch = Batch::new();
        // FIXME: why 2048?
        let max_batch_size = 2048;
        let mut count = 0;
        let mut set = self.clone();
        if flush {
            count += 1;
            batch.add(&set.flush_msg(), nftnl::MsgType::Del);
        }
        for net in cidrs.into_iter() {
            if count + 2 > max_batch_size {
                batch.add_iter(SetElemsIter::new(&set), MsgType::Add);
                send_and_process(socket, &batch.finalize())?;
                set = self.clone();
                batch = Batch::new();
            }
            match net {
                IpNet::V4(ip) => {
                    set.add_range(&ip.network(), cidr_bound_ipv4(ip).as_ref());
                }
                IpNet::V6(ip) => {
                    set.add_range(&ip.network(), cidr_bound_ipv6(ip).as_ref());
                }
            }
            count += 2;
        }
        batch.add_iter(SetElemsIter::new(&set), MsgType::Add);
        send_and_process(socket, &batch.finalize())
    }

    fn flush_msg(&self) -> FlushSetMsg<'_> {
        FlushSetMsg { set: self }
    }
}

impl Clone for Set1 {
    fn clone(&self) -> Self {
        Self(unsafe { nftnl_sys::nftnl_set_clone(self.0) })
    }
}

pub fn get_sets(socket: &mnl::Socket) -> io::Result<Vec<Set1>> {
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let seq = 0;
    let mut ret = Vec::new();
    unsafe {
        nftnl_sys::nftnl_nlmsg_build_hdr(
            buffer.as_mut_ptr() as *mut c_char,
            libc::NFT_MSG_GETSET as u16,
            nftnl::ProtoFamily::Inet as u16,
            (libc::NLM_F_DUMP | libc::NLM_F_ACK) as u16,
            seq,
        );
    }
    let cb = |header: &libc::nlmsghdr, ret: &mut Vec<Set1>| -> libc::c_int {
        unsafe {
            let set = Set1::new();
            let err = nftnl_sys::nftnl_set_nlmsg_parse(header, set.0);
            if err < 0 {
                return err;
            }
            ret.push(set);
        };
        1
    };
    socket.send(&buffer[..])?;

    // Try to parse the messages coming back from netfilter. This part is still very unclear.
    let portid = socket.portid();
    let mut buf = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let fd = unsafe { mnl_sys::mnl_socket_get_fd(socket.as_raw_socket()) };
    let mut readfds = nix::sys::select::FdSet::new();
    let fd1 = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut tv = nix::sys::time::TimeVal::new(0, 0);
    loop {
        readfds.clear();
        readfds.insert(fd1);
        if nix::sys::select::select(fd + 1, &mut readfds, None, None, &mut tv)? <= 0 {
            break;
        }
        if !readfds.contains(fd1) {
            break;
        }
        let msglen = socket.recv(&mut buf)?;
        match mnl::cb_run2(&buf[..msglen], 0, portid, cb, &mut ret)? {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }
    Ok(ret)
}

#[cfg(test)]
mod test {
    use std::net::Ipv6Addr;

    use ipnet::Ipv6Net;

    use super::get_sets;

    #[test]
    fn test_nftables() {
        let socket = mnl::Socket::new(mnl::Bus::Netfilter).unwrap();
        let sets = get_sets(&socket).unwrap();
        assert!(!sets.is_empty());
        for set in sets {
            if set.table_name() != Some("test") || set.name() != Some("test7") {
                continue;
            }
            set.add_cidrs(
                &socket,
                true,
                (0u128..8192u128)
                    .map(|x| ipnet::IpNet::V6(Ipv6Net::new(Ipv6Addr::from(x << 1), 127).unwrap())),
            )
            .unwrap();
            return;
        }
        panic!();
    }
}
