use std::{
    cell::Cell,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    os::raw::{c_char, c_void},
    rc::Rc,
};

use ipnet::{Ipv4Net, Ipv6Net};
use nftnl::{
    set::{Set, SetKey},
    FinalizedBatch, MsgType, NlMsg,
};

// internally represented as a range
struct Cidr<T>(T);
impl SetKey for Cidr<Ipv4Net> {
    const TYPE: u32 = Ipv4Addr::TYPE;
    const LEN: u32 = Ipv4Addr::LEN * 2;
    fn data(&self) -> Box<[u8]> {
        let data = u32::from_be_bytes(self.0.network().octets());
        let mask = u32::from_be_bytes(self.0.netmask().octets());
        let mut ret = [0u8; (Self::LEN) as usize];
        ret[..(Ipv4Addr::LEN as usize)].copy_from_slice(&self.0.network().octets());
        ret[(Ipv4Addr::LEN as usize)..].copy_from_slice(&u32::to_be_bytes(!mask | data));
        println!("{ret:?} {:?}", self.0.addr().data());
        Box::new(ret)
    }
}
impl SetKey for Cidr<Ipv6Net> {
    const TYPE: u32 = Ipv6Addr::TYPE;
    const LEN: u32 = Ipv6Addr::LEN * 2;
    fn data(&self) -> Box<[u8]> {
        let data = u128::from_be_bytes(self.0.network().octets());
        let mask = u128::from_be_bytes(self.0.netmask().octets());
        let mut ret = [0u8; (Self::LEN) as usize];
        ret[..(Ipv6Addr::LEN as usize)].copy_from_slice(&self.0.network().octets());
        ret[(Ipv6Addr::LEN as usize)..].copy_from_slice(&u128::to_be_bytes(!mask | data));
        Box::new(ret)
    }
}

struct FlushSetMsg<'a, T> {
    set: &'a Set<'a, T>,
}
unsafe impl<'a, T> NlMsg for FlushSetMsg<'a, T> {
    unsafe fn write(&self, buf: *mut std::ffi::c_void, seq: u32, _msg_type: MsgType) {
        let header = nftnl_sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            libc::NFT_MSG_DELSETELEM as u16,
            self.set.get_family() as u16,
            0,
            seq,
        );
        nftnl_sys::nftnl_set_elems_nlmsg_build_payload(header, self.set.as_ptr());
    }
}

pub fn send_and_process(batch: &FinalizedBatch) -> io::Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    eprintln!("a");
    socket.send_all(batch)?;
    eprintln!("b");
    let portid = socket.portid();
    let mut buf = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    loop {
        eprintln!("c");
        let n = socket.recv(&mut buf[..])?;
        eprintln!("d {n}");
        if n == 0 {
            break;
        }
        match mnl::cb_run(&buf[..n], 2, portid)? {
            mnl::CbResult::Stop => {
                println!("stop");
                break;
            }
            mnl::CbResult::Ok => {
                println!("ok");
            }
        }
    }
    Ok(())
}

pub struct SetElemsIter<'a, K> {
    set: &'a Set<'a, K>,
    iter: *mut nftnl_sys::nftnl_set_elems_iter,
    ret: Rc<Cell<i32>>,
    is_first: bool,
}

impl<'a, K> SetElemsIter<'a, K> {
    fn new(set: &'a Set<'a, K>) -> Self {
        let iter = unsafe { nftnl_sys::nftnl_set_elems_iter_create(set.as_ptr()) };
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

impl<'a, K: 'a> Iterator for SetElemsIter<'a, K> {
    type Item = SetElemsMsg<'a, K>;

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

impl<'a, K> Drop for SetElemsIter<'a, K> {
    fn drop(&mut self) {
        unsafe { nftnl_sys::nftnl_set_elems_iter_destroy(self.iter) };
    }
}

pub struct SetElemsMsg<'a, K> {
    set: &'a Set<'a, K>,
    iter: *mut nftnl_sys::nftnl_set_elems_iter,
    ret: Rc<Cell<i32>>,
}

unsafe impl<'a, K> NlMsg for SetElemsMsg<'a, K> {
    unsafe fn write(&self, buf: *mut c_void, seq: u32, msg_type: MsgType) {
        let (type_, flags) = match msg_type {
            MsgType::Add => (
                libc::NFT_MSG_NEWSETELEM,
                libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
            ),
            MsgType::Del => (libc::NFT_MSG_DELSETELEM, libc::NLM_F_ACK),
        };
        let header = nftnl_sys::nftnl_nlmsg_build_hdr(
            buf as *mut c_char,
            type_ as u16,
            self.set.get_family() as u16,
            flags as u16,
            seq,
        );
        self.ret
            .set(nftnl_sys::nftnl_set_elems_nlmsg_build_payload_iter(
                header, self.iter,
            ));
    }
}

fn add<K: SetKey>(set: &Set<K>, key: &K) {
    let data = key.data();
    let data_len = data.len() as u32;
    unsafe {
        let elem = nftnl_sys::nftnl_set_elem_alloc();
        if elem.is_null() {
            panic!("oom");
        }
        nftnl_sys::nftnl_set_elem_set(
            elem,
            nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
            data.as_ptr() as *const c_void,
            data_len / 2,
        );
        nftnl_sys::nftnl_set_elem_set_u32(
            elem,
            nftnl_sys::NFTNL_SET_ELEM_FLAGS as u16,
            1,
        );
        nftnl_sys::nftnl_set_elem_add(set.as_ptr(), elem);

        let elem = nftnl_sys::nftnl_set_elem_alloc();
        if elem.is_null() {
            panic!("oom");
        }
        nftnl_sys::nftnl_set_elem_set(
            elem,
            nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
            data.as_ptr().add((data_len / 2) as usize) as *const c_void,
            data_len / 2,
        );
        // nftnl_sys::nftnl_set_elem_set_u32(
        //     elem,
        //     nftnl_sys::NFTNL_SET_ELEM_FLAGS as u16,
        //     libc::NFT_SET_ELEM_INTERVAL_END as u32,
        // );
        nftnl_sys::nftnl_set_elem_add(set.as_ptr(), elem);
    }
}

#[cfg(test)]
mod test {
    use ipnet::Ipv4Net;
    use std::{
        ffi::CString,
        net::{IpAddr, Ipv4Addr},
    };

    use super::{add, send_and_process, Cidr, FlushSetMsg, SetElemsIter};

    #[test]
    fn test_nftables() {
        let table = nftnl::Table::new(
            &CString::from_vec_with_nul(b"test\0".to_vec()).unwrap(),
            nftnl::ProtoFamily::Inet,
        );
        let mut batch = nftnl::Batch::new();
        let mut set4 = nftnl::set::Set::<_>::new(
            &CString::from_vec_with_nul(b"test4\0".to_vec()).unwrap(),
            0,
            &table,
            nftnl::ProtoFamily::Inet,
        );
        batch.add(&FlushSetMsg { set: &set4 }, nftnl::MsgType::Del);
        add(
            &set4,
            &Cidr(Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 1), 32).unwrap()),
        );
        // set4.add(&Ipv4Addr::new(127, 0, 0, 1));
        let mut iter = SetElemsIter::new(&set4);
        batch.add_iter(iter, nftnl::MsgType::Add);
        send_and_process(&batch.finalize()).unwrap();
    }
}
