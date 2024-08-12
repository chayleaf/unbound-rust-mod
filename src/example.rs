use std::{
    collections::HashMap,
    fmt::Display,
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Mutex, RwLock,
    },
};

use ctor::ctor;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iptrie::{IpPrefix, RTrieSet};
use serde::{
    de::{Error, Visitor},
    Deserialize,
};
use smallvec::SmallVec;

use crate::{
    domain_tree::PrefixSet,
    nftables::{nftables_thread, NftData},
    unbound::{rr_class, rr_type, ModuleEvent, ModuleExtState, ReplyInfo},
    UnboundMod,
};

type Domain = SmallVec<[u8; 32]>;
type DomainSeg = SmallVec<[u8; 16]>;

struct IpNetDeser(IpNet);
struct IpNetVisitor;
impl<'de> Visitor<'de> for IpNetVisitor {
    type Value = IpNetDeser;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("ip address or cidr")
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if let Some((a, b)) = v.split_once('/') {
            let ip = IpAddr::from_str(a)
                .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &self))?;
            let len = u8::from_str(b)
                .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &self))?;
            IpNet::new(ip, len)
        } else {
            let ip = IpAddr::from_str(v)
                .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &self))?;
            IpNet::new(ip, if ip.is_ipv6() { 128 } else { 32 })
        }
        .map(IpNetDeser)
        .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &self))
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_borrowed_str(v)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_borrowed_str(&v)
    }
}

impl<'de> Deserialize<'de> for IpNetDeser {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(IpNetVisitor)
    }
}

#[derive(Default)]
struct ExampleMod {
    nft_token: Option<String>,
    tmp_nft_token: Option<String>,
    nft_queries: HashMap<String, NftQuery>,
    caches: (IpCache<Ipv4Addr>, IpCache<Ipv6Addr>),
    ruleset_queue: Option<mpsc::Sender<(SmallVec<[usize; 5]>, smallvec::SmallVec<[IpNet; 8]>)>>,
    error_lock: Mutex<()>,
    domains_write_lock: Mutex<()>,
}

struct IpCache<T>(
    RwLock<(
        radix_trie::Trie<IpCacheKey, usize>,
        Vec<(RwLock<smallvec::SmallVec<[T; 4]>>, Mutex<()>, AtomicBool)>,
    )>,
    PathBuf,
);

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct IpCacheKey(Domain);
impl radix_trie::TrieKey for IpCacheKey {
    fn encode_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl<T> Default for IpCache<T> {
    fn default() -> Self {
        Self(
            RwLock::new((radix_trie::Trie::new(), Vec::new())),
            PathBuf::new(),
        )
    }
}
fn ignore<T>(_: &mut smallvec::SmallVec<[T; 4]>) {}

impl<T> IpCache<T> {
    fn extend_set_with_domain<J: IpPrefix + From<T>>(&self, ips: &mut RTrieSet<J>, domain_r: Domain)
    where
        T: Copy,
    {
        self.get_maybe_update_rev(domain_r, |val| {
            if let Some(val) = val {
                ips.extend(val.0.iter().copied().map(|x| J::from(x)));
            }
            #[allow(unused_assignments)]
            let mut val = Some(ignore);
            val = None;
            val
        })
    }
    fn get_maybe_update_rev<F: for<'a> FnOnce(&'a mut smallvec::SmallVec<[T; 4]>)>(
        &self,
        domain_r: Domain,
        upd: impl FnOnce(Option<(&smallvec::SmallVec<[T; 4]>, &Mutex<()>, &AtomicBool)>) -> Option<F>,
    ) {
        let lock = self.0.read().unwrap();
        let domain_r = IpCacheKey(domain_r);
        let key = lock.0.get(&domain_r).copied();
        if let Some(val) = if let Some(x) = key.and_then(|key| lock.1.get(key)) {
            upd(Some((&x.0.read().unwrap(), &x.1, &x.2)))
        } else {
            upd(None)
        } {
            if let Some(key) = key {
                val(&mut *lock.1.get(key).unwrap().0.write().unwrap());
            } else {
                drop(lock);
                let mut lock = self.0.write().unwrap();
                if let Some(key) = lock.0.get(&domain_r).copied() {
                    val(&mut *lock.1.get(key).unwrap().0.write().unwrap());
                } else {
                    let key = lock.1.len();
                    lock.0.insert(domain_r, key);
                    let mut v = SmallVec::new();
                    val(&mut v);
                    lock.1
                        .push((RwLock::new(v), Mutex::new(()), AtomicBool::new(true)));
                }
            }
        }
    }
}

impl<T: ToString + PartialEq> IpCache<T> {
    fn set(&self, domain: &str, domain_r: IpCacheKey, val: smallvec::SmallVec<[T; 4]>) -> bool {
        let mut ret = true;
        let ret1 = &mut ret;
        let mut path = self.1.clone();
        path.push(domain);
        self.get_maybe_update_rev(domain_r.0, |ips| {
            if let Some(ips) = ips.as_ref().filter(|x| x.0 == &val) {
                *ret1 = false;
                if ips
                    .2
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    let _res = filetime::set_file_mtime(&path, filetime::FileTime::now());
                    #[cfg(test)]
                    _res.unwrap();
                }
                return None;
            }
            Some(|ips: &mut SmallVec<_>| {
                let Ok(mut file) = File::create(path) else {
                    *ips = val;
                    #[cfg(test)]
                    panic!();
                    #[cfg(not(test))]
                    return;
                };
                let to_write = val.iter().fold(String::new(), |mut s, ip| {
                    if !s.is_empty() {
                        s.push('\n');
                    }
                    s.push_str(&ip.to_string());
                    s
                });
                file.write_all(to_write.as_bytes()).unwrap_or(());
                *ips = val;
            })
        });
        ret
    }
}

impl<T: FromStr> IpCache<T> {
    fn load(&mut self, dir: &Path) -> Result<(), io::Error> {
        println!("loading {dir:?}");
        self.1 = dir.to_owned();
        std::fs::create_dir_all(dir)?;
        let mut lock = self.0.write().unwrap();
        assert!(lock.1.is_empty());
        let domains = std::fs::read_dir(dir)?;
        for entry in domains.filter_map(|x| x.ok()) {
            let domain = entry.file_name();
            let Some(domain) = domain.to_str() else {
                continue;
            };
            /*if let Some(age) = entry
                .metadata()
                .and_then(|x| x.modified())
                .ok()
                .and_then(|x| std::time::SystemTime::now().duration_since(x).ok())
            {
                if age > std::time::Duration::from_secs(60 * 60 * 24 * 7) {
                    continue;
                }
            }*/
            let Ok(reader) = std::fs::File::open(entry.path()) else {
                continue;
            };
            let domain_r = IpCacheKey(
                domain
                    .split('.')
                    .rev()
                    .map(|x| x.as_bytes())
                    .collect::<Vec<_>>()
                    .join(&b"."[..])
                    .into(),
            );
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            let mut ips = SmallVec::new();
            while matches!(reader.read_line(&mut line), Ok(x) if x > 0) {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                ips.extend(T::from_str(trimmed));
                line.clear();
            }
            if let Some(key) = lock.0.get(&domain_r).copied() {
                lock.1[key].0.write().unwrap().extend(ips);
            } else {
                let key = lock.1.len();
                lock.0.insert(domain_r, key);
                lock.1
                    .push((RwLock::new(ips), Mutex::new(()), AtomicBool::new(false)));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct NftQuery {
    domains: RwLock<PrefixSet<DomainSeg>>,
    dynamic: bool,
    index: usize,
}

#[cfg(debug_assertions)]
pub(crate) const DATA_PREFIX: &str = "unbound-mod-test-data";
#[cfg(debug_assertions)]
pub(crate) const CONFIG_PREFIX: &str = "unbound-mod-test-config";

#[cfg(not(debug_assertions))]
pub(crate) const PATH_PREFIX: &str = "/var/lib/unbound";
#[cfg(not(debug_assertions))]
pub(crate) const CONFIG_PREFIX: &str = "/etc/unbound";

impl ExampleMod {
    fn new() -> Result<Self, ()> {
        let mut ret = Self::default();
        let mut rulesets = ret.load_env()?;

        let mut base_path = PathBuf::from_str(DATA_PREFIX).unwrap();
        base_path.push("domains4");
        if let Err(err) = ret.caches.0.load(&base_path) {
            ret.report("domains4", err);
        }
        base_path.pop();
        base_path.push("domains6");
        if let Err(err) = ret.caches.1.load(&base_path) {
            ret.report("domains6", err);
        }

        ret.load_json(&mut rulesets);

        // it takes like 10 seconds to initialize nftables, so move it to a separate thread
        let (tx, rx) = mpsc::channel();
        ret.ruleset_queue = Some(tx);
        std::thread::spawn(move || nftables_thread(rulesets, rx));

        println!("loaded");

        Ok(ret)
    }
    fn load_json(&mut self, rulesets: &mut [(NftData<Ipv4Net>, NftData<Ipv6Net>)]) {
        for (k, v) in self.nft_queries.iter_mut() {
            let r = &mut rulesets[v.index];
            let mut v_domains = v.domains.write().unwrap();
            for base in [CONFIG_PREFIX, DATA_PREFIX] {
                if let Ok(file) = std::fs::File::open(format!("{base}/{k}_domains.json")) {
                    println!("loading {base}/{k}_domains.json");
                    match read_json::<Vec<String>>(file) {
                        Ok(domains) => {
                            for domain in domains {
                                v_domains.insert(
                                    domain
                                        .split('.')
                                        .rev()
                                        .map(|x| x.as_bytes().into())
                                        .collect::<SmallVec<[DomainSeg; 5]>>(),
                                );
                            }
                        }
                        Err(err) => Self::report2(&self.error_lock, "domains", err),
                    }
                }
                if let Ok(file) = std::fs::File::open(format!("{base}/{k}_dpi.json")) {
                    println!("loading {base}/{k}_dpi.json");
                    match read_json::<Vec<DpiInfo>>(file) {
                        Ok(dpi_info) => {
                            for domain in dpi_info.iter().flat_map(|x| &x.domains) {
                                v_domains.insert(
                                    domain
                                        .split('.')
                                        .rev()
                                        .map(|x| x.as_bytes().into())
                                        .collect::<SmallVec<[DomainSeg; 5]>>(),
                                );
                            }
                        }
                        Err(err) => Self::report2(&self.error_lock, "dpi", err),
                    }
                }
                if let Ok(file) = std::fs::File::open(format!("{base}/{k}_ips.json")) {
                    println!("loading {base}/{k}_ips.json");
                    match read_json::<Vec<IpNetDeser>>(file) {
                        Ok(ips) => {
                            r.0.extend(ips.iter().filter_map(|x| {
                                if let IpNet::V4(x) = x.0 {
                                    Some(x)
                                } else {
                                    None
                                }
                            }));
                            r.1.extend(ips.iter().filter_map(|x| {
                                if let IpNet::V6(x) = x.0 {
                                    Some(x)
                                } else {
                                    None
                                }
                            }));
                        }
                        Err(err) => Self::report2(&self.error_lock, "ips", err),
                    }
                }
            }
            println!("loading cached domain ips for {k}");
            for rev_domain in v_domains.iter() {
                let rev_domain: SmallVec<_> = rev_domain
                    .map(|x| x.as_slice())
                    .collect::<Vec<_>>()
                    .join(&b"."[..])
                    .into();
                self.caches
                    .0
                    .extend_set_with_domain(r.0.ips_mut(), rev_domain.clone());
                self.caches
                    .1
                    .extend_set_with_domain(r.1.ips_mut(), rev_domain.clone());
            }
        }
    }
    fn load_env(&mut self) -> Result<Vec<(NftData<Ipv4Net>, NftData<Ipv6Net>)>, ()> {
        self.nft_token = std::env::var_os("NFT_TOKEN")
            .map(|x| x.to_str().ok_or(()).map(|s| s.to_owned() + "."))
            .transpose()?;
        self.tmp_nft_token = std::env::var_os("NFT_TOKEN")
            .map(|x| x.to_str().ok_or(()).map(|s| format!("tmp{s}.")))
            .transpose()?;
        let mut rulesets = Vec::new();
        assert!(self.nft_queries.is_empty());
        if let Some(s) = std::env::var_os("NFT_QUERIES") {
            for (i, (name, set4, set6)) in s
                .to_str()
                .map(|x| x.to_owned())
                .ok_or(())?
                .split(';')
                .filter_map(|x| x.split_once(':'))
                .filter_map(|(name, sets)| {
                    sets.split_once(',').map(|(set4, set6)| (name, set4, set6))
                })
                .enumerate()
            {
                let (name, dynamic) = if let Some(name) = name.strip_suffix('!') {
                    (name, true)
                } else {
                    (name, false)
                };
                self.nft_queries.insert(
                    name.to_owned(),
                    NftQuery {
                        domains: RwLock::new(PrefixSet::new()),
                        dynamic,
                        index: i,
                    },
                );
                rulesets.push((NftData::new(set4), NftData::new(set6)));
            }
        }
        Ok(rulesets)
    }
    fn report2(error_lock: &Mutex<()>, code: &str, err: impl Display) {
        println!("{code}: {err}");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(format!("{DATA_PREFIX}/error.log"))
        {
            let _lock = error_lock.lock();
            if file.write_all(code.as_bytes()).is_err() {
                return;
            }
            if file.write_all(b": ").is_err() {
                return;
            }
            if file.write_all(err.to_string().as_bytes()).is_err() {
                return;
            }
            if file.write_all(b"\n").is_err() {
                return;
            }
            file.flush().unwrap_or(());
        }
    }
    fn report(&self, code: &str, err: impl Display) {
        Self::report2(&self.error_lock, code, err);
    }
    fn handle_reply_info(
        &self,
        split_rev_domain: SmallVec<[DomainSeg; 5]>,
        qnames: SmallVec<[usize; 5]>,
        rep: &ReplyInfo<'_>,
    ) -> Result<(), ()> {
        let mut ip4: SmallVec<[Ipv4Addr; 4]> = SmallVec::new();
        let mut ip6: SmallVec<[Ipv6Addr; 4]> = SmallVec::new();
        for rrset in rep.rrsets() {
            let entry = rrset.entry();
            let d = entry.data();
            let rk = rrset.rk();
            if rk.rrset_class() != rr_class::IN {
                continue;
            }
            for (data, _ttl) in d.rr_data() {
                match rk.type_() {
                    rr_type::A if data.len() == 2 + 4 && &data[..2] == b"\0\x04" => {
                        ip4.push(Ipv4Addr::from(
                            <[u8; 4]>::try_from(&data[2..2 + 4]).unwrap(),
                        ));
                    }
                    rr_type::AAAA if data.len() == 2 + 16 && &data[..2] == b"\0\x10" => {
                        ip6.push(Ipv6Addr::from(
                            <[u8; 16]>::try_from(&data[2..2 + 16]).unwrap(),
                        ));
                    }
                    _ => {}
                }
            }
        }
        self.add_ips(ip4, ip6, split_rev_domain, qnames)
    }
    fn add_ips(
        &self,
        ip4: SmallVec<[Ipv4Addr; 4]>,
        ip6: SmallVec<[Ipv6Addr; 4]>,
        split_rev_domain: SmallVec<[DomainSeg; 5]>,
        qnames: SmallVec<[usize; 5]>,
    ) -> Result<(), ()> {
        if !ip4.is_empty() || !ip6.is_empty() {
            let domain = match split_rev_domain
                .iter()
                .rev()
                .map(|x| String::from_utf8(x.to_vec()).map(|x| x + "."))
                .collect::<Result<String, _>>()
            {
                Ok(mut x) => {
                    x.pop();
                    x
                }
                Err(err) => {
                    self.report("domain utf-8", err);
                    return Err(());
                }
            };
            let mut split_rev_domain = split_rev_domain.into_iter();
            if let Some(first) = split_rev_domain.next() {
                let first: Domain = first.to_vec().into();
                let joined_rev_domain = split_rev_domain.fold(first, |mut res, mut next| {
                    res.push(b'.');
                    res.append(&mut next);
                    res
                });
                let mut to_send: SmallVec<[IpNet; 8]> = SmallVec::new();
                to_send.extend(ip4.iter().copied().map(Ipv4Net::from).map(IpNet::from));
                to_send.extend(ip6.iter().copied().map(Ipv6Net::from).map(IpNet::from));
                let keep4 = !ip4.is_empty()
                    && self
                        .caches
                        .0
                        .set(&domain, IpCacheKey(joined_rev_domain.clone()), ip4);
                let keep6 = !ip6.is_empty()
                    && self
                        .caches
                        .1
                        .set(&domain, IpCacheKey(joined_rev_domain.clone()), ip6);
                to_send.retain(|x| x.addr().is_ipv4() && keep4 || x.addr().is_ipv6() && keep6);
                if !to_send.is_empty() {
                    self.ruleset_queue
                        .as_ref()
                        .unwrap()
                        .send((qnames, to_send))
                        .unwrap();
                }
            }
        }
        Ok(())
    }
    fn run_commands(&self, rev_domain: &[u8]) -> Option<ModuleExtState> {
        if let Some(rev_domain) = self
            .nft_token
            .as_ref()
            .and_then(|token| rev_domain.strip_prefix(token.as_bytes()))
        {
            for (qname, query) in self.nft_queries.iter() {
                if query.dynamic && rev_domain.starts_with(qname.as_bytes()) {
                    if let Some(rev_domain) =
                        rev_domain.strip_prefix((qname.to_owned() + ".").as_bytes())
                    {
                        let rev_domain = rev_domain
                            .split(|x| *x == b'.')
                            .map(|x| x.into())
                            .collect::<SmallVec<[_; 5]>>();
                        let mut domains = query.domains.write().unwrap();
                        if domains.insert(rev_domain.clone()) {
                            drop(domains);
                            let file_name = format!("{DATA_PREFIX}/{qname}_domains.json");
                            let domain = match String::from_utf8(
                                rev_domain
                                    .iter()
                                    .rev()
                                    .map(|x| x.as_slice())
                                    .collect::<Vec<_>>()
                                    .join(&b"."[..]),
                            ) {
                                Ok(x) => x,
                                Err(err) => {
                                    self.report("domain utf-8", err);
                                    continue;
                                }
                            };
                            let _lock = self.domains_write_lock.lock().unwrap();
                            let mut old: Vec<String> = if let Ok(file) = File::open(&file_name) {
                                match read_json(file) {
                                    Ok(x) => x,
                                    Err(err) => {
                                        self.report("domains json", err);
                                        continue;
                                    }
                                }
                            } else {
                                vec![]
                            };
                            old.push(domain);
                            match File::create(file_name) {
                                Ok(file) => {
                                    if let Err(err) = serde_json::to_writer(file, &old) {
                                        self.report("domains write", err);
                                    }
                                }
                                Err(err) => self.report("domains create", err),
                            }
                        }
                    }
                }
            }
            return Some(ModuleExtState::Finished);
        } else if let Some(rev_domain) = self
            .tmp_nft_token
            .as_ref()
            .and_then(|token| rev_domain.strip_prefix(token.as_bytes()))
        {
            for (qname, query) in self.nft_queries.iter() {
                if query.dynamic && rev_domain.starts_with(qname.as_bytes()) {
                    if let Some(rev_domain) =
                        rev_domain.strip_prefix((qname.to_owned() + ".").as_bytes())
                    {
                        let rev_domain = rev_domain
                            .split(|x| *x == b'.')
                            .map(|x| x.into())
                            .collect::<SmallVec<[_; 5]>>();
                        let mut domains = query.domains.write().unwrap();
                        domains.insert(rev_domain.clone());
                    }
                }
            }
            return Some(ModuleExtState::Finished);
        }
        None
    }
    fn get_qnames(&self, split_rev_domain: &SmallVec<[DomainSeg; 5]>) -> SmallVec<[usize; 5]> {
        let mut qnames: SmallVec<[usize; 5]> = SmallVec::new();
        for query in self.nft_queries.values() {
            if query.domains.read().unwrap().contains(split_rev_domain) {
                qnames.push(query.index);
            }
        }
        qnames
    }
}

#[derive(Deserialize)]
struct DpiInfo {
    domains: Vec<String>,
    // name: String,
    // restriction: {"code": "ban"}
}

pub(crate) trait Helper: iptrie::IpPrefix + iptrie::IpRootPrefix + PartialEq {
    const ZERO: Self;
    fn direct_parent(&self) -> Option<Self>;
}

impl Helper for Ipv4Net {
    const ZERO: Self = match Self::new(Ipv4Addr::UNSPECIFIED, 0) {
        Ok(x) => x,
        #[allow(clippy::empty_loop)]
        Err(_) => loop {},
    };
    fn direct_parent(&self) -> Option<Self> {
        self.len()
            .checked_sub(1)
            .and_then(|x| Self::new(self.bitslot().into(), x).ok())
    }
}

impl Helper for Ipv6Net {
    const ZERO: Self = match Self::new(Ipv6Addr::UNSPECIFIED, 0) {
        Ok(x) => x,
        #[allow(clippy::empty_loop)]
        Err(_) => loop {},
    };
    fn direct_parent(&self) -> Option<Self> {
        self.len()
            .checked_sub(1)
            .and_then(|x| Self::new(self.bitslot().into(), x).ok())
    }
}
fn read_json<T: 'static + for<'a> Deserialize<'a>>(mut f: File) -> Result<T, serde_json::Error> {
    let mut data = Vec::new();
    f.read_to_end(&mut data)
        .map_err(serde_json::Error::custom)?;
    serde_json::from_slice(&data)
}

impl UnboundMod for ExampleMod {
    type EnvData = ();
    type QstateData = ();

    fn init(_env: &mut crate::unbound::ModuleEnv<Self::EnvData>) -> Result<Self, ()> {
        Self::new()
    }

    fn operate(
        &self,
        qstate: &mut crate::unbound::ModuleQstate<Self::QstateData>,
        event: ModuleEvent,
        _entry: &mut crate::unbound::OutboundEntryMut,
    ) -> Option<ModuleExtState> {
        match event {
            ModuleEvent::New | ModuleEvent::Pass => {
                return Some(ModuleExtState::WaitModule);
            }
            ModuleEvent::ModDone => {}
            _ => {
                return Some(ModuleExtState::Error);
            }
        }
        let info = qstate.qinfo_mut();
        let name = info.qname().to_bytes();
        let rev_domain = name.strip_suffix(b".").unwrap_or(name);
        if let Some(val) = self.run_commands(rev_domain) {
            return Some(val);
        }
        let split_rev_domain = rev_domain
            .split(|x| *x == b'.')
            .map(|x| x.into())
            .collect::<SmallVec<[_; 5]>>();
        let qnames = self.get_qnames(&split_rev_domain);
        if qnames.is_empty() {
            return Some(ModuleExtState::Finished);
        }
        if let Some(ret) = qstate.return_msg_mut() {
            if let Some(rep) = ret.rep() {
                if self
                    .handle_reply_info(split_rev_domain, qnames, &rep)
                    .is_err()
                {
                    return Some(ModuleExtState::Error);
                }
            }
        }
        Some(ModuleExtState::Finished)
    }
}

#[ctor]
fn setup() {
    crate::set_unbound_mod::<ExampleMod>();
}

#[cfg(test)]
mod test {
    use std::{net::Ipv4Addr, os::unix::fs::MetadataExt, path::PathBuf, str::FromStr, sync::mpsc};

    use ipnet::IpNet;
    use smallvec::{smallvec, SmallVec};

    use crate::example::{ignore, ExampleMod, IpNetDeser, DATA_PREFIX};

    #[test]
    fn test() {
        assert!(serde_json::from_str::<Vec<IpNetDeser>>(r#"["127.0.0.1/8","127.0.0.1"]"#).is_ok());
        #[cfg(not(debug_assertions))]
        return;

        std::fs::remove_dir_all(DATA_PREFIX).unwrap_or(());

        std::env::set_var("NFT_TOKEN", "token");
        std::env::set_var("NFT_QUERIES", "q!:set_a,set_b;w:set_c,set_d");

        std::fs::create_dir_all(DATA_PREFIX.to_string() + "/domains4").unwrap();
        std::fs::write(
            DATA_PREFIX.to_string() + "/domains4/a.com",
            "1.2.3.4\n5.6.7.8",
        )
        .unwrap();
        filetime::set_file_mtime(
            DATA_PREFIX.to_string() + "/domains4/a.com",
            filetime::FileTime::zero(),
        )
        .unwrap();

        std::fs::write(DATA_PREFIX.to_string() + "/domains4/b.com", "8.7.6.5").unwrap();
        std::fs::write(
            DATA_PREFIX.to_string() + "/q_domains.json",
            r#"["a.com","c.com"]"#,
        )
        .unwrap();
        std::fs::write(DATA_PREFIX.to_string() + "/q_ips.json", r#"["4.4.4.4"]"#).unwrap();
        std::fs::write(DATA_PREFIX.to_string() + "/w_domains.json", r#"["c.com"]"#).unwrap();
        std::fs::write(DATA_PREFIX.to_string() + "/w_ips.json", r#"["5.5.5.5"]"#).unwrap();

        let mut t = ExampleMod::default();
        let mut rulesets = t.load_env().unwrap();
        assert!(t.nft_queries.len() == 2 && rulesets.len() == t.nft_queries.len());
        assert!(t.nft_queries.get("q").unwrap().dynamic);
        assert!(!t.nft_queries.get("w").unwrap().dynamic);

        t.report("", "");
        std::fs::metadata(DATA_PREFIX.to_string() + "/error.log").unwrap();

        let mut base_path = PathBuf::from_str(DATA_PREFIX).unwrap();
        base_path.push("domains4");
        t.caches.0.load(&base_path).unwrap();
        base_path.pop();
        base_path.push("domains6");
        t.caches.1.load(&base_path).unwrap();

        t.caches
            .0
            .get_maybe_update_rev("com.a".as_bytes().into(), |x| {
                assert!(x.unwrap().0.len() == 2);
                #[allow(unused_assignments)]
                let mut val = Some(ignore);
                val = None;
                val
            });
        t.caches
            .0
            .get_maybe_update_rev("com.b".as_bytes().into(), |x| {
                assert!(x.unwrap().0.len() == 1);
                #[allow(unused_assignments)]
                let mut val = Some(ignore);
                val = None;
                val
            });

        t.load_json(&mut rulesets);

        assert_eq!(rulesets[0].0.ip_count(), 3);
        assert_eq!(rulesets[1].0.ip_count(), 1);

        let (tx, rx) = mpsc::channel();
        let (tx2, rx2) = mpsc::channel();

        t.ruleset_queue = Some(tx);

        std::thread::spawn(move || {
            while let Ok((rulesets1, ips)) = rx.recv() {
                for i in rulesets1.into_iter() {
                    let ruleset = &mut rulesets[i];
                    for ip1 in ips.iter().copied() {
                        match ip1 {
                            IpNet::V4(ip) => ruleset.0.insert(ip, true),
                            IpNet::V6(ip) => ruleset.1.insert(ip, true),
                        }
                    }
                }
            }
            tx2.send(rulesets).unwrap();
        });

        let split_rev_domain = smallvec![SmallVec::from(&b"com"[..]), SmallVec::from(&b"c"[..])];
        let qnames = t.get_qnames(&split_rev_domain);
        assert_eq!(qnames.len(), 2);
        t.add_ips(
            smallvec![Ipv4Addr::new(7, 7, 7, 7), Ipv4Addr::new(6, 6, 6, 6)],
            smallvec![],
            split_rev_domain,
            qnames,
        )
        .unwrap();

        let split_rev_domain = smallvec![SmallVec::from(&b"com"[..]), SmallVec::from(&b"a"[..])];
        let qnames = t.get_qnames(&split_rev_domain);
        t.add_ips(
            smallvec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)],
            smallvec![],
            split_rev_domain,
            qnames,
        )
        .unwrap();

        t.run_commands(b"token.q.com.w").unwrap();
        t.run_commands(b"tmptoken.q.com.e").unwrap();

        let split_rev_domain = smallvec![SmallVec::from(&b"com"[..]), SmallVec::from(&b"e"[..])];
        let qnames = t.get_qnames(&split_rev_domain);
        assert_eq!(qnames.len(), 1);
        t.add_ips(
            smallvec![Ipv4Addr::new(8, 8, 8, 8)],
            smallvec![],
            split_rev_domain,
            qnames,
        )
        .unwrap();

        let split_rev_domain = smallvec![SmallVec::from(&b"com"[..]), SmallVec::from(&b"w"[..])];
        let qnames = t.get_qnames(&split_rev_domain);
        assert_eq!(qnames.len(), 1);
        t.add_ips(
            smallvec![Ipv4Addr::new(9, 8, 8, 8)],
            smallvec![],
            split_rev_domain,
            qnames,
        )
        .unwrap();

        drop(t);
        let rulesets = rx2.recv().unwrap();

        std::fs::metadata(DATA_PREFIX.to_owned() + "/domains4/w.com").unwrap();
        assert_ne!(
            std::fs::metadata(DATA_PREFIX.to_string() + "/domains4/a.com")
                .unwrap()
                .mtime(),
            0
        );

        assert_eq!(rulesets[0].0.ip_count(), 7);
        assert_eq!(rulesets[1].0.ip_count(), 3);
    }
}
