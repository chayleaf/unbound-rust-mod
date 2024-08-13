use std::{
    cell::Cell,
    ffi::CStr,
    fmt::Display,
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
    os::{fd::BorrowedFd, raw::c_void},
    rc::Rc,
    sync::mpsc,
};

use crate::{Helper, DATA_PREFIX};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iptrie::RTrieSet;
use mnl::mnl_sys;
use nftnl::{nftnl_sys, set::SetKey, Batch, FinalizedBatch, MsgType, NlMsg};
use smallvec::SmallVec;

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
    unsafe fn write(&self, buf: *mut c_void, seq: u32, _msg_type: MsgType) {
        let header = nftnl_sys::nftnl_nlmsg_build_hdr(
            buf.cast(),
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
        assert!(!iter.is_null(), "oom");
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
            buf.cast(),
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
    pub const fn as_mut_ptr(&self) -> *mut nftnl_sys::nftnl_set {
        self.0
    }
    pub fn table_name(&self) -> Option<&CStr> {
        let ret =
            unsafe { nftnl_sys::nftnl_set_get_str(self.0, nftnl_sys::NFTNL_SET_TABLE as u16) };
        (!ret.is_null()).then(|| unsafe { CStr::from_ptr(ret) })
    }
    pub fn table_name_str(&self) -> Option<&str> {
        self.table_name().and_then(|s| s.to_str().ok())
    }
    pub fn set_table_name(&mut self, s: &CStr) -> Result<(), ()> {
        if unsafe {
            nftnl_sys::nftnl_set_set_str(self.0, nftnl_sys::NFTNL_SET_TABLE as u16, s.as_ptr())
        } == 0
        {
            Ok(())
        } else {
            Err(())
        }
    }
    pub fn name(&self) -> Option<&CStr> {
        let ret = unsafe { nftnl_sys::nftnl_set_get_str(self.0, nftnl_sys::NFTNL_SET_NAME as u16) };
        (!ret.is_null()).then(|| unsafe { CStr::from_ptr(ret) })
    }
    pub fn name_str(&self) -> Option<&str> {
        self.name().and_then(|s| s.to_str().ok())
    }
    pub fn set_name(&mut self, s: &CStr) -> Result<(), ()> {
        if unsafe {
            nftnl_sys::nftnl_set_set_str(self.0, nftnl_sys::NFTNL_SET_NAME as u16, s.as_ptr())
        } == 0
        {
            Ok(())
        } else {
            Err(())
        }
    }
    pub fn family(&self) -> u32 {
        unsafe { nftnl_sys::nftnl_set_get_u32(self.0, nftnl_sys::NFTNL_SET_FAMILY as u16) }
    }
    pub fn set_family(&mut self, val: u32) {
        unsafe { nftnl_sys::nftnl_set_set_u32(self.0, nftnl_sys::NFTNL_SET_FAMILY as u16, val) }
    }
    pub fn add_range<K: SetKey>(&mut self, lower: &K, excl_upper: Option<&K>) {
        let data1 = lower.data();
        let data1_len = data1.len() as u32;
        unsafe {
            let elem = nftnl_sys::nftnl_set_elem_alloc();
            assert!(!elem.is_null(), "oom");
            nftnl_sys::nftnl_set_elem_set(
                elem,
                nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                data1.as_ptr().cast(),
                data1_len,
            );
            nftnl_sys::nftnl_set_elem_add(self.as_mut_ptr(), elem);

            let Some(data2) = excl_upper.map(SetKey::data) else {
                return;
            };
            let data2_len = data2.len() as u32;

            let elem = nftnl_sys::nftnl_set_elem_alloc();
            assert!(!elem.is_null(), "oom");
            nftnl_sys::nftnl_set_elem_set(
                elem,
                nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                data2.as_ptr().cast(),
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
        let clone_self = || {
            let mut set = Self::new();
            if let Some(s) = self.table_name() {
                set.set_table_name(s).expect("oom");
            }
            if let Some(s) = self.name() {
                set.set_name(s).expect("oom");
            }
            let family = self.family();
            if family != 0 {
                set.set_family(self.family());
            }
            set
        };
        let mut set = clone_self();
        if flush {
            count += 1;
            batch.add(&set.flush_msg(), nftnl::MsgType::Del);
        }
        for net in cidrs {
            if count + 2 > max_batch_size {
                batch.add_iter(SetElemsIter::new(&set), MsgType::Add);
                send_and_process(socket, &batch.finalize())?;
                set = clone_self();
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

    const fn flush_msg(&self) -> FlushSetMsg<'_> {
        FlushSetMsg { set: self }
    }
}

pub fn get_sets(socket: &mnl::Socket) -> io::Result<Vec<Set1>> {
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let seq = 0;
    let mut ret = Vec::new();
    unsafe {
        nftnl_sys::nftnl_nlmsg_build_hdr(
            buffer.as_mut_ptr().cast(),
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

fn should_add<T: Helper>(trie: &RTrieSet<T>, elem: &T) -> bool {
    *trie.lookup(elem) == T::ZERO
}

fn iter_ip_trie<T: Helper>(trie: &RTrieSet<T>) -> impl '_ + Iterator<Item = T> {
    trie.iter().copied().filter(|x| {
        x.direct_parent()
            .map_or_else(|| *x != T::ZERO, |par| should_add(trie, &par))
    })
}

pub(crate) struct NftData<T: Helper> {
    all_ips: RTrieSet<T>,
    ips: RTrieSet<T>,
    set: Option<Set1>,
    name: String,
}

impl<T: Helper> NftData<T> {
    pub fn new(name: &str) -> Self {
        Self {
            set: None,
            ips: RTrieSet::new(),
            all_ips: RTrieSet::new(),
            name: name.to_owned(),
        }
    }
}

// SAFETY: set is None initially so Set1 is never actually sent
// (and it might be fine to send anyway actually)
unsafe impl<T: Helper + Send> Send for NftData<T> {}

impl<T: Helper> NftData<T>
where
    IpNet: From<T>,
{
    #[must_use]
    pub fn verify(&mut self) -> bool {
        if !self.name.is_empty() && self.set.is_none() {
            self.ips = RTrieSet::new();
            self.all_ips = RTrieSet::new();
            false
        } else {
            true
        }
    }
    fn dirty(&self) -> bool {
        usize::from(self.ips.len()) > 1
    }
    pub fn flush_changes(
        &mut self,
        socket: &mnl::Socket,
        flush_set: bool,
    ) -> Result<(), io::Error> {
        if !self.dirty() {
            return Ok(());
        }
        if let Some(set) = self.set.as_mut() {
            if flush_set {
                println!(
                    "initializing set {} with ~{} ips (e.g. {:?})",
                    self.name,
                    self.ips.len(),
                    iter_ip_trie(&self.ips).next(),
                );
            }
            let ret = set.add_cidrs(
                socket,
                flush_set,
                iter_ip_trie(&self.ips)
                    .map(|ip| {
                        self.all_ips.insert(ip);
                        ip
                    })
                    .map(IpNet::from),
            );
            self.ips = RTrieSet::new();
            ret
        } else {
            Ok(())
        }
    }
    pub fn extend(&mut self, ips: impl Iterator<Item = T>) {
        for ip in ips {
            self.insert(ip, true);
        }
    }
    pub fn insert(&mut self, ip: T, allow_empty_set: bool) {
        if (if allow_empty_set {
            !self.name.is_empty()
        } else {
            self.set.is_some()
        }) && should_add(&self.all_ips, &ip)
            && should_add(&self.ips, &ip)
        {
            self.ips.insert(ip);
        }
    }
    #[cfg(test)]
    pub fn ip_count(&self) -> usize {
        iter_ip_trie(&self.ips).count()
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn set_set(&mut self, set: Set1) {
        self.set = Some(set);
    }
}

pub(crate) fn nftables_thread(
    mut rulesets: Vec<(NftData<Ipv4Net>, NftData<Ipv6Net>)>,
    rx: mpsc::Receiver<(SmallVec<[usize; 5]>, smallvec::SmallVec<[IpNet; 8]>)>,
) {
    fn report(err: impl Display) {
        println!("nftables: {err}");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(format!("{DATA_PREFIX}/nftables.log"))
        {
            file.write_all((err.to_string() + "\n").as_bytes())
                .unwrap_or(());
        }
    }
    let socket = mnl::Socket::new(mnl::Bus::Netfilter).unwrap();
    let all_sets = get_sets(&socket).unwrap();
    for set in all_sets {
        for ruleset in &mut rulesets {
            if set.table_name_str() == Some("global") && set.family() == libc::NFPROTO_INET as u32 {
                if set.name_str() == Some(ruleset.0.name()) {
                    println!("found set {}", ruleset.0.name());
                    ruleset.0.set_set(set);
                    break;
                } else if set.name_str() == Some(ruleset.1.name()) {
                    println!("found set {}", ruleset.1.name());
                    ruleset.1.set_set(set);
                    break;
                }
            }
        }
    }
    for ruleset in &mut rulesets {
        if !ruleset.0.verify() {
            report(format!("set {} not found", ruleset.0.name()));
        }
        if !ruleset.1.verify() {
            report(format!("set {} not found", ruleset.1.name()));
        }
    }
    let mut first = true;
    loop {
        for ruleset in &mut rulesets {
            if let Err(err) = ruleset.0.flush_changes(&socket, first) {
                report(err);
            }
            if let Err(err) = ruleset.1.flush_changes(&socket, first) {
                report(err);
            }
        }
        if first {
            println!("nftables init done");
            first = false;
        }
        let Ok((rulesets1, ips)) = rx.recv() else {
            break;
        };
        for i in rulesets1 {
            let ruleset = &mut rulesets[i];
            for ip1 in ips.iter().copied() {
                match ip1 {
                    IpNet::V4(ip) => ruleset.0.insert(ip, false),
                    IpNet::V6(ip) => ruleset.1.insert(ip, false),
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use ipnet::{Ipv4Net, Ipv6Net};
    use iptrie::RTrieSet;

    use super::{get_sets, iter_ip_trie, should_add};

    #[test]
    fn test_nftables() {
        if !nix::unistd::Uid::effective().is_root() {
            return;
        }
        let socket = mnl::Socket::new(mnl::Bus::Netfilter).unwrap();
        let sets = get_sets(&socket).unwrap();
        assert!(!sets.is_empty());
        for set in sets {
            // add set inet test test7 { type ipv6_addr ; flags interval ; }
            if set.table_name_str() != Some("test") || set.name_str() != Some("test7") {
                continue;
            }
            // must end with ::3ffe/127
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

    #[test]
    fn test_set() {
        let mut trie = RTrieSet::new();
        assert!(should_add(
            &trie,
            &Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 1), 32).unwrap()
        ));
        trie.insert(Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 1), 32).unwrap());
        assert!(!should_add(
            &trie,
            &Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 1), 32).unwrap()
        ));
        trie.insert(Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 1), 31).unwrap());
        assert!(dbg!(iter_ip_trie(&trie).collect::<Vec<_>>()).len() == 1);
        // contains 0.0.0.0, etc
        assert!(dbg!(trie.iter().collect::<Vec<_>>()).len() == 3);
        trie.insert(Ipv4Net::new(Ipv4Addr::new(127, 0, 1, 1), 32).unwrap());
        assert!(dbg!(iter_ip_trie(&trie).collect::<Vec<_>>()).len() == 2);
    }
}
