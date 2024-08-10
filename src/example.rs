use std::{
    collections::HashMap,
    fmt::Display,
    fs::File,
    io::{self, BufRead, BufReader, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        mpsc::{self, RecvError},
        Mutex, RwLock,
    },
    time::{Duration, SystemTime},
};

use ctor::ctor;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iptrie::{IpPrefix, RTrieSet};
use prefix_tree::PrefixSet;
use serde::Deserialize;
use smallvec::SmallVec;

use crate::{
    nftables::Set1,
    unbound::{rr_class, rr_type},
    UnboundMod,
};

type Domain = SmallVec<[u8; 32]>;
type DomainSeg = SmallVec<[u8; 16]>;

#[derive(Default)]
struct ExampleMod {
    domain_name_overrides: HashMap<Domain, Domain>,
    nft_token: Option<String>,
    tmp_nft_token: Option<String>,
    nft_queries: HashMap<String, NftQuery>,
    cache4: IpCache<Ipv4Addr>,
    cache6: IpCache<Ipv6Addr>,
    #[allow(clippy::type_complexity)]
    ruleset_queue: Option<mpsc::Sender<(SmallVec<[usize; 5]>, smallvec::SmallVec<[IpNet; 8]>)>>,
    error_lock: Mutex<()>,
    domains_write_lock: Mutex<()>,
}

#[allow(clippy::type_complexity)]
struct IpCache<T>(
    RwLock<(
        radix_trie::Trie<IpCacheKey, usize>,
        Vec<(RwLock<smallvec::SmallVec<[T; 4]>>, Mutex<()>)>,
    )>,
    PathBuf,
);

#[repr(transparent)]
#[derive(PartialEq, Eq)]
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

impl<T> IpCache<T> {
    fn get_maybe_update_rev(
        &self,
        domain_r: Domain,
        upd: impl FnOnce(Option<&smallvec::SmallVec<[T; 4]>>) -> Option<smallvec::SmallVec<[T; 4]>>,
    ) {
        let lock = self.0.read().unwrap();
        let domain_r = IpCacheKey(domain_r);
        let key = lock.0.get(&domain_r).copied();
        if let Some(val) = if let Some(key) = key {
            upd(lock.1.get(key).map(|x| x.0.read().unwrap()).as_deref())
        } else {
            upd(None)
        } {
            if let Some(key) = key {
                *lock.1.get(key).unwrap().0.write().unwrap() = val;
            } else {
                drop(lock);
                let mut lock = self.0.write().unwrap();
                let key = lock.1.len();
                lock.0.insert(domain_r, key).unwrap();
                lock.1.push((RwLock::new(val), Mutex::new(())));
            }
        }
    }
}

impl<T: ToString + PartialEq> IpCache<T> {
    fn set(&self, domain: &str, domain_r: IpCacheKey, val: smallvec::SmallVec<[T; 4]>) -> bool {
        let lock = self.0.read().unwrap();
        let key = lock.0.get(&domain_r).copied();
        let to_write = val
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let mut path = self.1.clone();
        path.push(domain);
        let finish = move |_lock| {
            let Ok(mut file) = File::create(path) else {
                return;
            };
            file.write_all(to_write.as_bytes()).unwrap_or(());
        };
        if let Some(key) = key {
            let mut lock = lock.1.get(key).unwrap().0.write().unwrap();
            if *lock == val {
                return false;
            }
            *lock = val;
            finish(lock);
        } else {
            drop(lock);
            let mut lock = self.0.write().unwrap();
            let key = lock.1.len();
            lock.0.insert(domain_r, key).unwrap();
            lock.1.push((RwLock::new(val), Mutex::new(())));
            drop(lock);
            finish(
                self.0
                    .read()
                    .unwrap()
                    .1
                    .get(key)
                    .unwrap()
                    .0
                    .write()
                    .unwrap(),
            );
        }
        true
    }
}

impl<T: FromStr> IpCache<T> {
    fn load(&mut self, dir: &Path) -> Result<(), io::Error> {
        std::fs::create_dir_all(dir)?;
        let mut lock = self.0.write().unwrap();
        assert!(lock.1.is_empty());
        let domains = std::fs::read_dir("/var/lib/unbound/domains4/")?;
        for entry in domains.filter_map(|x| x.ok()) {
            let domain = entry.file_name();
            let Some(domain) = domain.to_str() else {
                continue;
            };
            if let Some(age) = entry
                .metadata()
                .and_then(|x| x.modified())
                .ok()
                .and_then(|x| SystemTime::now().duration_since(x).ok())
            {
                if age > Duration::from_secs(60 * 60 * 24 * 7) {
                    continue;
                }
            }
            let domain_r = IpCacheKey(
                domain
                    .split('.')
                    .rev()
                    .map(|x| x.as_bytes())
                    .collect::<Vec<_>>()
                    .join(&b"."[..])
                    .into(),
            );
            let key = lock.1.len();
            lock.0.insert(domain_r, key).unwrap();
            let Ok(reader) = std::fs::File::open(entry.path()) else {
                continue;
            };
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            let mut ips = SmallVec::new();
            while reader.read_line(&mut line).is_ok() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                ips.extend(T::from_str(trimmed));
                line.clear();
            }
            lock.1.push((RwLock::new(ips), Mutex::new(())));
        }
        Ok(())
    }
}

struct NftData {
    ips4: RTrieSet<Ipv4Net>,
    ips6: RTrieSet<Ipv6Net>,
    dirty4: bool,
    dirty6: bool,
    set4: Option<Set1>,
    set6: Option<Set1>,
    name4: String,
    name6: String,
}

// SAFETY: set4/set6 are None initially and are never actually sent
unsafe impl Send for NftData {}

struct NftQuery {
    domains: RwLock<prefix_tree::PrefixSet<DomainSeg>>,
    dynamic: bool,
    index: usize,
}

impl ExampleMod {
    fn report(&self, code: &str, err: impl Display) {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .open("/var/lib/unbound/error.log")
        {
            let _lock = self.error_lock.lock();
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
}

#[derive(Deserialize)]
struct DpiInfo {
    domains: Vec<String>,
    // name: String,
    // restriction: {"code": "ban"}
}

trait Helper: iptrie::IpPrefix + PartialEq {
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

fn should_add<T: Helper>(trie: &RTrieSet<T>, elem: &T) -> bool {
    *trie.lookup(elem) == T::ZERO
}

fn iter_ip_trie<T: Helper>(trie: &RTrieSet<T>) -> impl '_ + Iterator<Item = T> {
    trie.iter().copied().filter(|x| {
        if let Some(par) = x.direct_parent() {
            should_add(trie, &par)
        } else {
            *x != T::ZERO
        }
    })
}

impl UnboundMod for ExampleMod {
    type EnvData = ();
    type QstateData = ();
    fn init(_env: &mut crate::unbound::ModuleEnv<Self::EnvData>) -> Result<Self, ()> {
        let mut ret = Self {
            nft_token: std::env::var_os("NFT_TOKEN")
                .map(|x| x.to_str().ok_or(()).map(|s| s.to_owned() + "."))
                .transpose()?,
            tmp_nft_token: std::env::var_os("NFT_TOKEN")
                .map(|x| x.to_str().ok_or(()).map(|s| s.to_owned() + ".tmp."))
                .transpose()?,
            ..Self::default()
        };
        if let Some(s) = std::env::var_os("DOMAIN_NAME_OVERRIDES") {
            for (k, v) in s
                .to_str()
                .map(|x| x.to_owned())
                .ok_or(())?
                .split(';')
                .filter_map(|x| x.split_once("->"))
            {
                ret.domain_name_overrides
                    .insert(k.as_bytes().into(), v.as_bytes().into());
            }
        }
        let mut nft_queries = HashMap::new();
        let mut rulesets = Vec::new();
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
                nft_queries.insert(
                    name.to_owned(),
                    NftQuery {
                        domains: RwLock::new(PrefixSet::new()),
                        dynamic,
                        index: i,
                    },
                );
                rulesets.push(NftData {
                    set4: None,
                    set6: None,
                    ips4: RTrieSet::new(),
                    ips6: RTrieSet::new(),
                    dirty4: true,
                    dirty6: true,
                    name4: set4.to_owned(),
                    name6: set6.to_owned(),
                });
            }
        }

        // load cached domains
        if let Err(err) = ret.cache4.load(Path::new("/var/lib/unbound/domains4/")) {
            ret.report("domains4", err);
        }
        if let Err(err) = ret.cache6.load(Path::new("/var/lib/unbound/domains6/")) {
            ret.report("domains6", err);
        }

        // load json files
        for ((k, v), r) in nft_queries.iter_mut().zip(rulesets.iter_mut()) {
            for base in ["/etc/unbound", "/var/lib/unbound"] {
                let mut v_domains = v.domains.write().unwrap();
                if let Ok(file) = std::fs::File::open(format!("{base}/{k}_domains.json")) {
                    match serde_json::from_reader::<_, Vec<String>>(file) {
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
                        Err(err) => ret.report("domains", err),
                    }
                }
                if let Ok(file) = std::fs::File::open(format!("{base}/{k}_dpi.json")) {
                    match serde_json::from_reader::<_, Vec<DpiInfo>>(file) {
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
                        Err(err) => ret.report("dpi", err),
                    }
                }
                if let Ok(file) = std::fs::File::open(format!("{base}/{k}_ips.json")) {
                    match serde_json::from_reader::<_, Vec<IpNet>>(file) {
                        Ok(ips) => {
                            r.ips4.extend(ips.iter().filter_map(|x| {
                                if let IpNet::V4(x) = x {
                                    Some(*x)
                                } else {
                                    None
                                }
                            }));
                            r.ips6.extend(ips.iter().filter_map(|x| {
                                if let IpNet::V6(x) = x {
                                    Some(*x)
                                } else {
                                    None
                                }
                            }));
                        }
                        Err(err) => ret.report("ips", err),
                    }
                }
                for rev_domain in v_domains.iter() {
                    ret.cache4.get_maybe_update_rev(
                        rev_domain
                            .iter()
                            .map(|x| x.as_slice())
                            .collect::<Vec<_>>()
                            .join(&b"."[..])
                            .into(),
                        |val| {
                            if let Some(val) = val {
                                r.ips4.extend(val.iter().map(|x| Ipv4Net::from(*x)));
                            }
                            None
                        },
                    );
                    ret.cache6.get_maybe_update_rev(
                        rev_domain
                            .iter()
                            .map(|x| x.as_slice())
                            .collect::<Vec<_>>()
                            .join(&b"."[..])
                            .into(),
                        |val| {
                            if let Some(val) = val {
                                r.ips6.extend(val.iter().map(|x| Ipv6Net::from(*x)));
                            }
                            None
                        },
                    );
                }
            }
        }

        // add stuff to nftables
        let (tx, rx) = mpsc::channel();

        ret.ruleset_queue = Some(tx);

        std::thread::spawn(move || {
            fn report(err: impl Display) {
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .append(true)
                    .open("/var/lib/unbound/nftables.log")
                {
                    if file.write_all(err.to_string().as_bytes()).is_err() {
                        return;
                    }
                    if file.write_all(b"\n").is_err() {
                        return;
                    }
                    file.flush().unwrap_or(());
                }
            }
            let socket = mnl::Socket::new(mnl::Bus::Netfilter).unwrap();
            let all_sets = crate::nftables::get_sets(&socket).unwrap();
            for set in all_sets {
                for ruleset in &mut rulesets {
                    if set.table_name() == Some("global")
                        && set.family() == libc::NFPROTO_INET as u32
                    {
                        if set.name() == Some(&ruleset.name4) {
                            ruleset.set4 = Some(set.clone());
                        } else if set.name() == Some(&ruleset.name6) {
                            ruleset.set6 = Some(set.clone());
                        }
                    }
                }
            }
            for ruleset in &mut rulesets {
                if !ruleset.name4.is_empty() && ruleset.set4.is_none() {
                    report(format!("set {} not found", ruleset.name4));
                    ruleset.ips4 = RTrieSet::new();
                }
                if !ruleset.name6.is_empty() && ruleset.set6.is_none() {
                    report(format!("set {} not found", ruleset.name6));
                    ruleset.ips6 = RTrieSet::new();
                }
            }
            let mut first = true;
            loop {
                for ruleset in &mut rulesets {
                    if let Some(set) = ruleset.set4.as_mut().filter(|_| ruleset.dirty4) {
                        if let Err(err) = set.add_cidrs(
                            &socket,
                            first,
                            iter_ip_trie(&ruleset.ips4).map(IpNet::V4),
                        ) {
                            report(err);
                        }
                    }
                    if let Some(set) = ruleset.set6.as_mut().filter(|_| ruleset.dirty6) {
                        if let Err(err) = set.add_cidrs(
                            &socket,
                            first,
                            iter_ip_trie(&ruleset.ips6).map(IpNet::V6),
                        ) {
                            report(err);
                        }
                    }
                }
                first = false;
                let res = match rx.recv() {
                    Ok(val) => Some(val),
                    Err(RecvError) => break,
                };
                if let Some((rulesets1, ips)) = res {
                    for i in rulesets1.into_iter() {
                        let ruleset = &mut rulesets[i];
                        for ip1 in ips.iter().copied() {
                            match ip1 {
                                IpNet::V4(ip) => {
                                    if ruleset.set4.is_some() && !should_add(&ruleset.ips4, &ip) {
                                        ruleset.ips4.insert(ip);
                                        ruleset.dirty4 = true;
                                    }
                                }
                                IpNet::V6(ip) => {
                                    if ruleset.set6.is_some() && !should_add(&ruleset.ips6, &ip) {
                                        ruleset.ips6.insert(ip);
                                        ruleset.dirty6 = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(ret)
    }

    fn operate(
        &self,
        qstate: &mut crate::unbound::ModuleQstate<Self::QstateData>,
        _event: crate::unbound::ModuleEvent,
        _entry: &mut crate::unbound::OutboundEntryMut,
    ) {
        let info = qstate.qinfo_mut();
        let name = info.qname().to_bytes();
        let rev_domain = name.strip_suffix(b".").unwrap_or(name);
        if let Some(rev_domain) = self
            .nft_token
            .as_ref()
            .and_then(|token| rev_domain.strip_prefix(token.as_bytes()))
        {
            for (qname, query) in self.nft_queries.iter() {
                if query.dynamic && rev_domain.ends_with(qname.as_bytes()) {
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
                            let file_name = format!("/var/lib/unbound/{qname}_domains.json");
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
                                match serde_json::from_reader(file) {
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
            return;
        } else if let Some(rev_domain) = self
            .tmp_nft_token
            .as_ref()
            .and_then(|token| rev_domain.strip_prefix(token.as_bytes()))
        {
            for (qname, query) in self.nft_queries.iter() {
                if query.dynamic && rev_domain.ends_with(qname.as_bytes()) {
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
            return;
        }
        let split_rev_domain = rev_domain
            .split(|x| *x == b'.')
            .map(|x| x.into())
            .collect::<SmallVec<[_; 5]>>();
        let mut qnames: SmallVec<[usize; 5]> = SmallVec::new();
        for query in self.nft_queries.values() {
            if query.domains.read().unwrap().contains(&split_rev_domain) {
                qnames.push(query.index);
            }
        }
        if qnames.is_empty() {
            return;
        }
        if let Some(ret) = qstate.return_msg_mut() {
            if let Some(rep) = ret.rep() {
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
                            return;
                        }
                    };
                    let mut split_rev_domain = split_rev_domain.into_iter();
                    if let Some(first) = split_rev_domain.next() {
                        let first: Domain = first.to_vec().into();
                        let joined_rev_domain =
                            split_rev_domain.fold(first, |mut res, mut next| {
                                res.push(b'.');
                                res.append(&mut next);
                                res
                            });
                        let mut to_send: SmallVec<[IpNet; 8]> = SmallVec::new();
                        to_send.extend(ip4.iter().copied().map(Ipv4Net::from).map(IpNet::from));
                        to_send.extend(ip6.iter().copied().map(Ipv6Net::from).map(IpNet::from));
                        let keep4 = !ip4.is_empty()
                            && self
                                .cache4
                                .set(&domain, IpCacheKey(joined_rev_domain.clone()), ip4);
                        let keep6 = !ip6.is_empty()
                            && self
                                .cache6
                                .set(&domain, IpCacheKey(joined_rev_domain.clone()), ip6);
                        to_send
                            .retain(|x| x.addr().is_ipv4() && keep4 || x.addr().is_ipv6() && keep6);
                        if !to_send.is_empty() {
                            self.ruleset_queue
                                .as_ref()
                                .unwrap()
                                .send((qnames, to_send))
                                .unwrap();
                        }
                    }
                }
            }
        }
    }
}

#[ctor]
fn setup() {
    crate::set_unbound_mod::<ExampleMod>();
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;
    use iptrie::RTrieSet;

    use crate::example::{iter_ip_trie, should_add};

    #[test]
    fn test() {
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
