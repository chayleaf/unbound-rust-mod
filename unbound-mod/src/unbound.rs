#![allow(dead_code)]
use crate::bindings::{
    self, module_env, module_ev, module_ext_state, module_qstate, rrset_id_type, rrset_trust,
    sec_status, sldns_enum_ede_code,
};
use std::{
    ffi::CStr,
    marker::PhantomData,
    ops::Deref,
    os::raw::{c_char, c_int},
    ptr,
    time::Duration,
};

macro_rules! create_struct {
    ($ptr:tt, $name:tt, $mut:tt) => {
        #[repr(transparent)]
        pub struct $name<'a>(
            pub(crate) *mut bindings::$ptr,
            pub(crate) PhantomData<&'a bindings::$ptr>,
        );
        #[repr(transparent)]
        pub struct $mut<'a>(pub(crate) $name<'a>);
        impl<'a> Deref for $mut<'a> {
            type Target = $name<'a>;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl<'a> $name<'a> {
            pub const fn as_ptr(&self) -> *const bindings::$ptr {
                self.0.cast_const()
            }
            pub unsafe fn from_raw(raw: *const bindings::$ptr) -> Option<Self> {
                (!raw.is_null()).then_some(Self(raw.cast_mut(), PhantomData))
            }
        }
        impl<'a> $mut<'a> {
            pub fn as_mut_ptr(&mut self) -> *mut bindings::$ptr {
                self.0 .0
            }
            pub unsafe fn from_raw(raw: *mut bindings::$ptr) -> Option<Self> {
                (!raw.is_null()).then_some(Self($name(raw, PhantomData)))
            }
        }
    };
}

macro_rules! create_enums {
    {
        $(#[repr($repr:ident/$typ:ty)]
        enum $name:ident {
            $($(#[doc = $doc:literal])?
            $member:ident = $value:ident,)*
        })*
    } => {
        $(
        #[non_exhaustive]
        #[repr($repr)]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
        pub enum $name {
            $($(#[doc = $doc])?
            $member = bindings::$value,)*
            #[doc(hidden)]
            Unknown = 9999,
        }
        impl From<$typ> for $name {
            fn from(x: $typ) -> Self {
                match x {
                    $(bindings::$value => Self::$member,)*
                    _ => Self::Unknown,
                }
            }
        }
        )*
    }
}

create_struct!(config_file, ConfigFile, ConfigFileMut);
create_struct!(slabhash, SlabHash, SlabHashMut);
create_struct!(rrset_cache, RrsetCache, RrsetCacheMut);
create_struct!(infra_cache, InfraCache, InfraCacheMut);
create_struct!(key_cache, KeyCache, KeyCacheMut);
create_struct!(outbound_entry, OutboundEntry, OutboundEntryMut);
create_struct!(query_info, QueryInfo, QueryInfoMut);
create_struct!(dns_msg, DnsMsg, DnsMsgMut);
create_struct!(reply_info, ReplyInfo, ReplyInfoMut);
create_struct!(ub_packed_rrset_key, UbPackedRrsetKey, UbPackedRrsetKeyMut);
create_struct!(lruhash_entry, LruHashEntry, LruHashEntryMut);
create_struct!(packed_rrset_key, PackedRrsetKey, PackedRrsetKeyMut);
create_struct!(packed_rrset_data, PackedRrsetData, PackedRrsetDataMut);

pub struct ModuleEnv<'a, T>(
    pub(crate) *mut module_env,
    pub(crate) c_int,
    pub(crate) PhantomData<&'a T>,
);
pub struct ModuleEnvMut<'a, T>(pub(crate) ModuleEnv<'a, T>);
impl<'a, T> Deref for ModuleEnvMut<'a, T> {
    type Target = ModuleEnv<'a, T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
pub struct ModuleQstate<'a, T>(
    pub(crate) *mut module_qstate,
    pub(crate) c_int,
    pub(crate) PhantomData<&'a mut T>,
);
pub struct ModuleQstateMut<'a, T>(pub(crate) ModuleQstate<'a, T>);
impl<'a, T> Deref for ModuleQstateMut<'a, T> {
    type Target = ModuleQstate<'a, T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> QueryInfo<'a> {
    pub fn qname(&self) -> &CStr {
        unsafe { CStr::from_ptr((*self.as_ptr()).qname as *const c_char) }
    }
    pub fn qtype(&self) -> u16 {
        unsafe { (*self.as_ptr()).qtype }
    }
    pub fn qclass(&self) -> u16 {
        unsafe { (*self.as_ptr()).qclass }
    }
}

impl<'a, T> ModuleEnv<'a, T> {
    pub unsafe fn from_raw(raw: *mut bindings::module_env, id: c_int) -> Option<Self> {
        (!raw.is_null()).then_some(Self(raw, id, PhantomData))
    }
    pub const fn as_ptr(&self) -> *const module_env {
        self.0.cast_const()
    }
    pub fn config_file(&self) -> ConfigFile<'_> {
        unsafe { ConfigFile::from_raw((*self.as_ptr()).cfg).unwrap() }
    }
    pub fn msg_cache(&self) -> SlabHash<'_> {
        unsafe { SlabHash::from_raw((*self.as_ptr()).msg_cache) }.unwrap()
    }
    pub fn rrset_cache(&self) -> RrsetCache<'_> {
        unsafe { RrsetCache::from_raw((*self.as_ptr()).rrset_cache) }.unwrap()
    }
    pub fn infra_cache(&self) -> InfraCache<'_> {
        unsafe { InfraCache::from_raw((*self.as_ptr()).infra_cache) }.unwrap()
    }
    pub fn key_cache(&self) -> KeyCache<'_> {
        unsafe { KeyCache::from_raw((*self.as_ptr()).key_cache) }.unwrap()
    }
}
impl<'a, T> ModuleEnvMut<'a, T> {
    pub unsafe fn from_raw(raw: *mut bindings::module_env, id: c_int) -> Option<Self> {
        ModuleEnv::from_raw(raw, id).map(Self)
    }
    pub fn as_mut_ptr(&mut self) -> *mut module_env {
        self.0 .0
    }
    // FIXME: what lifetime to use?
    // #[allow(clippy::too_many_arguments)]
    // pub fn send_query<Y>(
    //     &mut self,
    //     qinfo: &QueryInfoMut,
    //     flags: u16,
    //     dnssec: u32,
    //     want_dnssec: bool,
    //     nocaps: bool,
    //     check_ratelimit: bool,
    //     addr: SocketAddr,
    //     zone: &[u8],
    //     tcp_upstream: bool,
    //     ssl_upstream: bool,
    //     tls_auth_name: Option<&CStr>,
    //     q: &mut ModuleQstate<Y>,
    // ) -> (Option<OutboundEntryMut<'_>>, bool) {
    //     let mut was_ratelimited = 0;
    //     let ret = unsafe {
    //         let mut addr4 = sockaddr_in {
    //             sin_port: 0,
    //             sin_addr: in_addr { s_addr: 0 },
    //             sin_zero: [0u8; 8],
    //             sin_family: AF_INET as u16,
    //         };
    //         let mut addr6 = sockaddr_in6 {
    //             sin6_port: 0,
    //             sin6_addr: in6_addr {
    //                 __in6_u: in6_addr__bindgen_ty_1 {
    //                     __u6_addr8: [0u8; 16],
    //                 },
    //             },
    //             sin6_family: AF_INET6 as u16,
    //             sin6_flowinfo: 0,
    //             sin6_scope_id: 0,
    //         };
    //         let (addr, addr_len) = match addr {
    //             SocketAddr::V4(x) => {
    //                 addr4.sin_port = x.port();
    //                 addr4.sin_addr.s_addr = (*x.ip()).into();
    //                 (
    //                     ptr::addr_of!(addr4).cast::<sockaddr_storage>(),
    //                     mem::size_of_val(&addr4),
    //                 )
    //             }
    //             SocketAddr::V6(x) => {
    //                 addr6.sin6_addr.__in6_u.__u6_addr8 = x.ip().octets();
    //                 addr6.sin6_flowinfo = x.flowinfo();
    //                 addr6.sin6_scope_id = x.scope_id();
    //                 (
    //                     ptr::addr_of!(addr6).cast(),
    //                     mem::size_of_val(&addr6),
    //                 )
    //             }
    //         };
    //         ((*self.as_ptr()).send_query.unwrap_unchecked())(
    //             qinfo.as_ptr(),
    //             flags,
    //             dnssec as i32,
    //             want_dnssec.into(),
    //             nocaps.into(),
    //             check_ratelimit.into(),
    //             addr.cast_mut(),
    //             addr_len as u32,
    //             zone.as_ptr().cast_mut(),
    //             zone.len(),
    //             tcp_upstream.into(),
    //             ssl_upstream.into(),
    //             tls_auth_name.map_or_else(ptr::null_mut, |x| x.as_ptr().cast_mut()),
    //             q.as_ptr(),
    //             ptr::addr_of_mut!(was_ratelimited),
    //         )
    //     };
    //     if ret.is_null() {
    //         (None, was_ratelimited != 0)
    //     } else {
    //         (
    //             Some(OutboundEntryMut(OutboundEntry(ret, PhantomData))),
    //             was_ratelimited != 0,
    //         )
    //     }
    // }
    pub fn detach_subs<Y>(&mut self, qstate: &mut ModuleQstateMut<Y>) {
        unsafe { (*self.as_ptr()).detach_subs.unwrap()(qstate.as_mut_ptr()) }
    }
    // FIXME: what lifetime to use?
    // unsafe fn attach_sub<Y>(
    //     &mut self,
    //     qstate: &mut ModuleQstate<Y>,
    //     qinfo: &QueryInfoMut,
    //     qflags: u16,
    //     prime: bool,
    //     valrec: bool,
    //     init_sub: impl FnOnce(*mut module_qstate) -> Result<(), ()>,
    // ) -> Result<Option<ModuleQstate<'_, ()>>, ()> {
    //     let mut newq: *mut module_qstate = ptr::null_mut();
    //     let res = unsafe {
    //         ((*self.as_ptr()).attach_sub.unwrap_unchecked())(
    //             qstate.as_ptr(),
    //             qinfo.as_ptr(),
    //             qflags,
    //             prime.into(),
    //             valrec.into(),
    //             &mut newq as _,
    //         )
    //     };
    //     if res != 0 {
    //         Ok(if newq.is_null() {
    //             None
    //         } else if init_sub(newq).is_ok() {
    //             Some(ModuleQstate(newq, qstate.1, PhantomData))
    //         } else {
    //             unsafe { ((*self.as_ptr()).kill_sub.unwrap_unchecked())(newq) }
    //             return Err(());
    //         })
    //     } else {
    //         Err(())
    //     }
    // }
    // add_sub: TODO similar to above
    // detect_cycle: TODO
    // (note that &mut T is wrapped in dynmod stuff)
    // fn modinfo_mut(&mut self) -> Option<&mut T> {}
}

impl<T> ModuleQstate<'_, T> {
    pub unsafe fn from_raw(raw: *mut bindings::module_qstate, id: c_int) -> Option<Self> {
        (!raw.is_null()).then_some(Self(raw, id, PhantomData))
    }
    pub const fn as_ptr(&self) -> *const module_qstate {
        self.0.cast_const()
    }
    pub fn qinfo(&self) -> QueryInfo<'_> {
        unsafe { QueryInfo::from_raw(ptr::addr_of!((*self.as_ptr()).qinfo).cast_mut()).unwrap() }
    }
    pub fn return_msg(&self) -> Option<DnsMsg<'_>> {
        unsafe { DnsMsg::from_raw((*self.as_ptr()).return_msg) }
    }
}
pub(crate) fn check_id(id: i32) -> Option<usize> {
    (id >= 0 && id < bindings::MAX_MODULE as i32).then_some(id as usize)
}
impl<T> ModuleQstateMut<'_, T> {
    pub unsafe fn from_raw(raw: *mut bindings::module_qstate, id: c_int) -> Option<Self> {
        ModuleQstate::from_raw(raw, id).map(Self)
    }
    pub fn as_mut_ptr(&mut self) -> *mut module_qstate {
        self.0 .0
    }
    pub fn qinfo_mut(&mut self) -> QueryInfoMut<'_> {
        QueryInfoMut(self.qinfo())
    }
    pub fn return_msg_mut(&mut self) -> Option<DnsMsgMut<'_>> {
        self.return_msg().map(DnsMsgMut)
    }
    pub fn set_ext_state(&mut self, state: ModuleExtState) {
        unsafe {
            if let Some(id) = check_id(self.1) {
                (*self.as_mut_ptr()).ext_state[id] = state as module_ext_state;
            }
        }
    }
}

impl DnsMsg<'_> {
    pub fn rep(&self) -> Option<ReplyInfo<'_>> {
        unsafe { ReplyInfo::from_raw((*self.as_ptr()).rep) }
    }
}

impl ReplyInfo<'_> {
    pub fn flags(&self) -> u16 {
        unsafe { (*self.as_ptr()).flags }
    }
    pub fn authoritative(&self) -> bool {
        unsafe { (*self.as_ptr()).authoritative != 0 }
    }
    pub fn qdcount(&self) -> u8 {
        unsafe { (*self.as_ptr()).qdcount }
    }
    pub fn padding(&self) -> u32 {
        unsafe { (*self.as_ptr()).padding }
    }
    pub fn ttl(&self) -> Option<Duration> {
        (unsafe { (*self.as_ptr()).ttl })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn prefetch_ttl(&self) -> Option<Duration> {
        (unsafe { (*self.as_ptr()).prefetch_ttl })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn serve_expired_ttl(&self) -> Option<Duration> {
        (unsafe { (*self.as_ptr()).serve_expired_ttl })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn security(&self) -> SecStatus {
        SecStatus::from(unsafe { (*self.as_ptr()).security })
    }
    pub fn reason_bogus(&self) -> SldnsEdeCode {
        SldnsEdeCode::from(unsafe { (*self.as_ptr()).reason_bogus })
    }
    pub fn reason_bogus_str(&self) -> Option<&CStr> {
        if unsafe { (*self.as_ptr()).reason_bogus_str.is_null() } {
            None
        } else {
            Some(unsafe { CStr::from_ptr((*self.as_ptr()).reason_bogus_str) })
        }
    }
    pub fn an_numrrsets(&self) -> usize {
        unsafe { (*self.as_ptr()).an_numrrsets }
    }
    pub fn ns_numrrsets(&self) -> usize {
        unsafe { (*self.as_ptr()).ns_numrrsets }
    }
    pub fn ar_numrrsets(&self) -> usize {
        unsafe { (*self.as_ptr()).ar_numrrsets }
    }
    pub fn rrset_count(&self) -> usize {
        unsafe { (*self.as_ptr()).rrset_count }
    }
    pub fn rrsets(&self) -> impl '_ + Iterator<Item = UbPackedRrsetKey<'_>> {
        let total = self.rrset_count();
        let rrsets = unsafe { (*self.as_ptr()).rrsets };
        (0..total).filter_map(move |i| unsafe { UbPackedRrsetKey::from_raw(*rrsets.add(i)) })
    }
}

impl UbPackedRrsetKey<'_> {
    pub fn entry(&self) -> LruHashEntry<'_> {
        unsafe { LruHashEntry::from_raw(ptr::addr_of!((*self.as_ptr()).entry).cast_mut()).unwrap() }
    }
    pub fn id(&self) -> RrsetIdType {
        unsafe { (*self.as_ptr()).id }
    }
    pub fn rk(&self) -> PackedRrsetKey<'_> {
        unsafe { PackedRrsetKey::from_raw(ptr::addr_of!((*self.as_ptr()).rk).cast_mut()).unwrap() }
    }
}

impl PackedRrsetKey<'_> {
    pub fn dname(&self) -> Option<&'_ CStr> {
        if unsafe { (*self.as_ptr()).dname.is_null() } {
            None
        } else {
            Some(unsafe { CStr::from_ptr((*self.as_ptr()).dname as *const c_char) })
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe { (*self.as_ptr()).flags }
    }
    pub fn type_(&self) -> u16 {
        u16::from_be(unsafe { (*self.as_ptr()).type_ })
    }
    pub fn rrset_class(&self) -> u16 {
        u16::from_be(unsafe { (*self.as_ptr()).rrset_class })
    }
}

impl LruHashEntry<'_> {
    pub fn data(&self) -> Option<PackedRrsetData<'_>> {
        // FIXME: shouldnt pthread lock be used here?
        unsafe { PackedRrsetData::from_raw((*self.as_ptr()).data.cast()) }
    }
}

impl PackedRrsetData<'_> {
    pub fn ttl_add(&self) -> Option<Duration> {
        (unsafe { (*self.as_ptr()).ttl_add })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn ttl(&self) -> Option<Duration> {
        (unsafe { (*self.as_ptr()).ttl })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn count(&self) -> usize {
        unsafe { (*self.as_ptr()).count }
    }
    pub fn rrsig_count(&self) -> usize {
        unsafe { (*self.as_ptr()).rrsig_count }
    }
    pub fn trust(&self) -> RrsetTrust {
        RrsetTrust::from(unsafe { (*self.as_ptr()).trust })
    }
    pub fn security(&self) -> SecStatus {
        SecStatus::from(unsafe { (*self.as_ptr()).security })
    }
    pub fn rr_data(&self) -> impl '_ + Iterator<Item = (&[u8], Option<Duration>)> {
        let total = self.count();
        let ttl = unsafe { (*self.as_ptr()).rr_ttl };
        let len = unsafe { (*self.as_ptr()).rr_len };
        let data = unsafe { (*self.as_ptr()).rr_data };
        (0..total).map(move |i| unsafe {
            (
                std::slice::from_raw_parts(*data.add(i), *len.add(i)),
                TryFrom::try_from(*ttl.add(i)).map(Duration::from_secs).ok(),
            )
        })
    }
    pub fn rrsig_data(&self) -> impl '_ + Iterator<Item = &[u8]> {
        let total = self.count();
        let total2 = self.rrsig_count();
        let len = unsafe { (*self.as_ptr()).rr_len };
        let data = unsafe { (*self.as_ptr()).rr_data };
        (total..total + total2)
            .map(move |i| unsafe { std::slice::from_raw_parts(*data.add(i), *len.add(i)) })
    }
}

type RrsetIdType = rrset_id_type;

create_enums! {
    #[repr(u32/module_ev)]
    enum ModuleEvent {
        #[doc = " new query"]
        New = module_ev_module_event_new,
        #[doc = " query passed by other module"]
        Pass = module_ev_module_event_pass,
        #[doc = " reply inbound from server"]
        Reply = module_ev_module_event_reply,
        #[doc = " no reply, timeout or other error"]
        NoReply = module_ev_module_event_noreply,
        #[doc = " reply is there, but capitalisation check failed"]
        CapsFail = module_ev_module_event_capsfail,
        #[doc = " next module is done, and its reply is awaiting you"]
        ModDone = module_ev_module_event_moddone,
        #[doc = " error"]
        Error = module_ev_module_event_error,
    }

    #[repr(u32/sec_status)]
    enum SecStatus {
        #[doc = " UNCHECKED means that object has yet to be validated."]
        Unchecked = sec_status_sec_status_unchecked,
        #[doc = " BOGUS means that the object (RRset or message) failed to validate\n  (according to local policy), but should have validated."]
        Bogus = sec_status_sec_status_bogus,
        #[doc = " INDETERMINATE means that the object is insecure, but not\n authoritatively so. Generally this means that the RRset is not\n below a configured trust anchor."]
        Indeterminate = sec_status_sec_status_indeterminate,
        #[doc = " INSECURE means that the object is authoritatively known to be\n insecure. Generally this means that this RRset is below a trust\n anchor, but also below a verified, insecure delegation."]
        Insecure = sec_status_sec_status_insecure,
        #[doc = " SECURE_SENTINEL_FAIL means that the object (RRset or message)\n validated according to local policy but did not succeed in the root\n KSK sentinel test (draft-ietf-dnsop-kskroll-sentinel)."]
        SecureSentinelFail = sec_status_sec_status_secure_sentinel_fail,
        #[doc = " SECURE means that the object (RRset or message) validated\n according to local policy."]
        Secure = sec_status_sec_status_secure,
    }

    #[repr(i32/sldns_enum_ede_code)]
    enum SldnsEdeCode {
        None = sldns_enum_ede_code_LDNS_EDE_NONE,
        Other = sldns_enum_ede_code_LDNS_EDE_OTHER,
        UnsupportedDnskeyAlg = sldns_enum_ede_code_LDNS_EDE_UNSUPPORTED_DNSKEY_ALG,
        UnsupportedDsDigest = sldns_enum_ede_code_LDNS_EDE_UNSUPPORTED_DS_DIGEST,
        StaleAnswer = sldns_enum_ede_code_LDNS_EDE_STALE_ANSWER,
        ForgedAnswer = sldns_enum_ede_code_LDNS_EDE_FORGED_ANSWER,
        DnssecIndeterminate = sldns_enum_ede_code_LDNS_EDE_DNSSEC_INDETERMINATE,
        DnssecBogus = sldns_enum_ede_code_LDNS_EDE_DNSSEC_BOGUS,
        SignatureExpired = sldns_enum_ede_code_LDNS_EDE_SIGNATURE_EXPIRED,
        SignatureNotYetValid = sldns_enum_ede_code_LDNS_EDE_SIGNATURE_NOT_YET_VALID,
        DnskeyMissing = sldns_enum_ede_code_LDNS_EDE_DNSKEY_MISSING,
        RrsigsMissing = sldns_enum_ede_code_LDNS_EDE_RRSIGS_MISSING,
        NoZoneKeyBitSet = sldns_enum_ede_code_LDNS_EDE_NO_ZONE_KEY_BIT_SET,
        NsecMissing = sldns_enum_ede_code_LDNS_EDE_NSEC_MISSING,
        CachedError = sldns_enum_ede_code_LDNS_EDE_CACHED_ERROR,
        NotReady = sldns_enum_ede_code_LDNS_EDE_NOT_READY,
        Blocked = sldns_enum_ede_code_LDNS_EDE_BLOCKED,
        Censored = sldns_enum_ede_code_LDNS_EDE_CENSORED,
        Filtered = sldns_enum_ede_code_LDNS_EDE_FILTERED,
        Prohibited = sldns_enum_ede_code_LDNS_EDE_PROHIBITED,
        StaleNxdomainAnswer = sldns_enum_ede_code_LDNS_EDE_STALE_NXDOMAIN_ANSWER,
        NotAuthoritative = sldns_enum_ede_code_LDNS_EDE_NOT_AUTHORITATIVE,
        NotSupported = sldns_enum_ede_code_LDNS_EDE_NOT_SUPPORTED,
        NoReachableAuthority = sldns_enum_ede_code_LDNS_EDE_NO_REACHABLE_AUTHORITY,
        NetworkError = sldns_enum_ede_code_LDNS_EDE_NETWORK_ERROR,
        InvalidData = sldns_enum_ede_code_LDNS_EDE_INVALID_DATA,
    }

    #[repr(u32/rrset_trust)]
    enum RrsetTrust {
        #[doc = " initial value for trust"]
        None = rrset_trust_rrset_trust_none,
        #[doc = " Additional information from non-authoritative answers"]
        AddNoAa = rrset_trust_rrset_trust_add_noAA,
        #[doc = " Data from the authority section of a non-authoritative answer"]
        AuthNoAa = rrset_trust_rrset_trust_auth_noAA,
        #[doc = " Additional information from an authoritative answer"]
        AddAa = rrset_trust_rrset_trust_add_AA,
        #[doc = " non-authoritative data from the answer section of authoritative\n answers"]
        NonauthAnsAa = rrset_trust_rrset_trust_nonauth_ans_AA,
        #[doc = " Data from the answer section of a non-authoritative answer"]
        AnsNoAa = rrset_trust_rrset_trust_ans_noAA,
        #[doc = " Glue from a primary zone, or glue from a zone transfer"]
        Glue = rrset_trust_rrset_trust_glue,
        #[doc = " Data from the authority section of an authoritative answer"]
        AuthAa = rrset_trust_rrset_trust_auth_AA,
        #[doc = " The authoritative data included in the answer section of an\n  authoritative reply"]
        AnsAa = rrset_trust_rrset_trust_ans_AA,
        #[doc = " Data from a zone transfer, other than glue"]
        SecNoglue = rrset_trust_rrset_trust_sec_noglue,
        #[doc = " Data from a primary zone file, other than glue data"]
        PrimNoglue = rrset_trust_rrset_trust_prim_noglue,
        #[doc = " DNSSEC(rfc4034) validated with trusted keys"]
        Validated = rrset_trust_rrset_trust_validated,
        #[doc = " ultimately trusted, no more trust is possible;\n trusted keys from the unbound configuration setup."]
        Ultimate = rrset_trust_rrset_trust_ultimate,
    }

    #[repr(u32/module_ext_state)]
    enum ModuleExtState {
        #[doc = " initial state - new query"]
        InitialState = module_ext_state_module_state_initial,
        #[doc = " waiting for reply to outgoing network query"]
        WaitReply = module_ext_state_module_wait_reply,
        #[doc = " module is waiting for another module"]
        WaitModule = module_ext_state_module_wait_module,
        #[doc = " module is waiting for another module; that other is restarted"]
        RestartNext = module_ext_state_module_restart_next,
        #[doc = " module is waiting for sub-query"]
        WaitSubquery = module_ext_state_module_wait_subquery,
        #[doc = " module could not finish the query"]
        Error = module_ext_state_module_error,
        #[doc = " module is finished with query"]
        Finished = module_ext_state_module_finished,
    }
}

impl ModuleExtState {
    pub(crate) const fn importance(self) -> usize {
        match self {
            Self::Unknown => 0,
            Self::InitialState => 1,
            Self::Finished => 2,
            Self::WaitModule => 3,
            Self::RestartNext => 4,
            Self::WaitSubquery => 5,
            Self::WaitReply => 6,
            Self::Error => 7,
        }
    }
}

pub mod rr_class {
    use crate::bindings;
    /// the Internet
    pub const IN: u16 = bindings::sldns_enum_rr_class_LDNS_RR_CLASS_IN as u16;
    /// Chaos class
    pub const CH: u16 = bindings::sldns_enum_rr_class_LDNS_RR_CLASS_CH as u16;
    /// Hesiod (Dyer 87)
    pub const HS: u16 = bindings::sldns_enum_rr_class_LDNS_RR_CLASS_HS as u16;
    /// None class, dynamic update
    pub const NONE: u16 = bindings::sldns_enum_rr_class_LDNS_RR_CLASS_NONE as u16;
    /// Any class
    pub const ANY: u16 = bindings::sldns_enum_rr_class_LDNS_RR_CLASS_ANY as u16;
}

pub mod rr_type {
    use crate::bindings;
    #[doc = "  a host address"]
    pub const A: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_A as u16;
    #[doc = "  an authoritative name server"]
    pub const NS: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NS as u16;
    #[doc = "  a mail destination (Obsolete - use MX)"]
    pub const MD: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_MD as u16;
    #[doc = "  a mail forwarder (Obsolete - use MX)"]
    pub const MF: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_MF as u16;
    #[doc = "  the canonical name for an alias"]
    pub const CNAME: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_CNAME as u16;
    #[doc = "  marks the start of a zone of authority"]
    pub const SOA: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_SOA as u16;
    #[doc = "  a mailbox domain name (EXPERIMENTAL)"]
    pub const MB: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_MB as u16;
    #[doc = "  a mail group member (EXPERIMENTAL)"]
    pub const MG: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_MG as u16;
    #[doc = "  a mail rename domain name (EXPERIMENTAL)"]
    pub const MR: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_MR as u16;
    #[doc = "  a null RR (EXPERIMENTAL)"]
    pub const NULL: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NULL as u16;
    #[doc = "  a well known service description"]
    pub const WKS: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_WKS as u16;
    #[doc = "  a domain name pointer"]
    pub const PTR: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_PTR as u16;
    #[doc = "  host information"]
    pub const HINFO: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_HINFO as u16;
    #[doc = "  mailbox or mail list information"]
    pub const MINFO: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_MINFO as u16;
    #[doc = "  mail exchange"]
    pub const MX: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_MX as u16;
    #[doc = "  text strings"]
    pub const TXT: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_TXT as u16;
    #[doc = "  RFC1183"]
    pub const RP: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_RP as u16;
    #[doc = "  RFC1183"]
    pub const AFSDB: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_AFSDB as u16;
    #[doc = "  RFC1183"]
    pub const X25: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_X25 as u16;
    #[doc = "  RFC1183"]
    pub const ISDN: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_ISDN as u16;
    #[doc = "  RFC1183"]
    pub const RT: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_RT as u16;
    #[doc = "  RFC1706"]
    pub const NSAP: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NSAP as u16;
    #[doc = "  RFC1348"]
    pub const NSAP_PTR: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NSAP_PTR as u16;
    #[doc = "  2535typecode"]
    pub const SIG: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_SIG as u16;
    #[doc = "  2535typecode"]
    pub const KEY: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_KEY as u16;
    #[doc = "  RFC2163"]
    pub const PX: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_PX as u16;
    #[doc = "  RFC1712"]
    pub const GPOS: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_GPOS as u16;
    #[doc = "  ipv6 address"]
    pub const AAAA: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_AAAA as u16;
    #[doc = "  LOC record  RFC1876"]
    pub const LOC: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_LOC as u16;
    #[doc = "  2535typecode"]
    pub const NXT: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NXT as u16;
    #[doc = "  draft-ietf-nimrod-dns-01.txt"]
    pub const EID: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_EID as u16;
    #[doc = "  draft-ietf-nimrod-dns-01.txt"]
    pub const NIMLOC: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NIMLOC as u16;
    #[doc = "  SRV record RFC2782"]
    pub const SRV: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_SRV as u16;
    #[doc = "  http://www.jhsoft.com/rfc/af-saa-0069.000.rtf"]
    pub const ATMA: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_ATMA as u16;
    #[doc = "  RFC2915"]
    pub const NAPTR: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NAPTR as u16;
    #[doc = "  RFC2230"]
    pub const KX: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_KX as u16;
    #[doc = "  RFC2538"]
    pub const CERT: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_CERT as u16;
    #[doc = "  RFC2874"]
    pub const A6: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_A6 as u16;
    #[doc = "  RFC2672"]
    pub const DNAME: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_DNAME as u16;
    #[doc = "  dnsind-kitchen-sink-02.txt"]
    pub const SINK: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_SINK as u16;
    #[doc = "  Pseudo OPT record..."]
    pub const OPT: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_OPT as u16;
    #[doc = "  RFC3123"]
    pub const APL: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_APL as u16;
    #[doc = "  RFC4034, RFC3658"]
    pub const DS: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_DS as u16;
    #[doc = "  SSH Key Fingerprint"]
    pub const SSHFP: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_SSHFP as u16;
    #[doc = "  IPsec Key"]
    pub const IPSECKEY: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_IPSECKEY as u16;
    #[doc = "  DNSSEC"]
    pub const RRSIG: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_RRSIG as u16;
    #[doc = "  DNSSEC"]
    pub const NSEC: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NSEC as u16;
    #[doc = "  DNSSEC"]
    pub const DNSKEY: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_DNSKEY as u16;
    #[doc = "  DNSSEC"]
    pub const DHCID: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_DHCID as u16;
    #[doc = "  DNSSEC"]
    pub const NSEC3: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NSEC3 as u16;
    #[doc = "  DNSSEC"]
    pub const NSEC3PARAM: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NSEC3PARAM as u16;
    #[doc = "  DNSSEC"]
    pub const NSEC3PARAMS: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NSEC3PARAMS as u16;
    #[doc = "  DNSSEC"]
    pub const TLSA: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_TLSA as u16;
    #[doc = "  DNSSEC"]
    pub const SMIMEA: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_SMIMEA as u16;
    #[doc = "  DNSSEC"]
    pub const HIP: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_HIP as u16;
    #[doc = " draft-reid-dnsext-zs"]
    pub const NINFO: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NINFO as u16;
    #[doc = " draft-reid-dnsext-rkey"]
    pub const RKEY: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_RKEY as u16;
    #[doc = " draft-ietf-dnsop-trust-history"]
    pub const TALINK: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_TALINK as u16;
    #[doc = " draft-ietf-dnsop-trust-history"]
    pub const CDS: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_CDS as u16;
    #[doc = " RFC 7344"]
    pub const CDNSKEY: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_CDNSKEY as u16;
    #[doc = " RFC 7344"]
    pub const OPENPGPKEY: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_OPENPGPKEY as u16;
    #[doc = " RFC 7344"]
    pub const CSYNC: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_CSYNC as u16;
    #[doc = " RFC 7344"]
    pub const ZONEMD: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_ZONEMD as u16;
    #[doc = " RFC 7344"]
    pub const SVCB: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_SVCB as u16;
    #[doc = " RFC 7344"]
    pub const HTTPS: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_HTTPS as u16;
    #[doc = " RFC 7344"]
    pub const SPF: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_SPF as u16;
    #[doc = " RFC 7344"]
    pub const UINFO: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_UINFO as u16;
    #[doc = " RFC 7344"]
    pub const UID: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_UID as u16;
    #[doc = " RFC 7344"]
    pub const GID: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_GID as u16;
    #[doc = " RFC 7344"]
    pub const UNSPEC: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_UNSPEC as u16;
    #[doc = " RFC 7344"]
    pub const NID: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_NID as u16;
    #[doc = " RFC 7344"]
    pub const L32: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_L32 as u16;
    #[doc = " RFC 7344"]
    pub const L64: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_L64 as u16;
    #[doc = " RFC 7344"]
    pub const LP: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_LP as u16;
    #[doc = " draft-jabley-dnsext-eui48-eui64-rrtypes"]
    pub const EUI48: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_EUI48 as u16;
    #[doc = " draft-jabley-dnsext-eui48-eui64-rrtypes"]
    pub const EUI64: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_EUI64 as u16;
    #[doc = " draft-jabley-dnsext-eui48-eui64-rrtypes"]
    pub const TKEY: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_TKEY as u16;
    #[doc = " draft-jabley-dnsext-eui48-eui64-rrtypes"]
    pub const TSIG: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_TSIG as u16;
    #[doc = " draft-jabley-dnsext-eui48-eui64-rrtypes"]
    pub const IXFR: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_IXFR as u16;
    #[doc = " draft-jabley-dnsext-eui48-eui64-rrtypes"]
    pub const AXFR: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_AXFR as u16;
    #[doc = "  A request for mailbox-related records (MB, MG or MR)"]
    pub const MAILB: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_MAILB as u16;
    #[doc = "  A request for mail agent RRs (Obsolete - see MX)"]
    pub const MAILA: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_MAILA as u16;
    #[doc = "  any type (wildcard)"]
    pub const ANY: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_ANY as u16;
    #[doc = "  any type (wildcard)"]
    pub const URI: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_URI as u16;
    #[doc = "  any type (wildcard)"]
    pub const CAA: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_CAA as u16;
    #[doc = "  any type (wildcard)"]
    pub const AVC: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_AVC as u16;
    #[doc = " DNSSEC Trust Authorities"]
    pub const TA: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_TA as u16;
    #[doc = " DNSSEC Trust Authorities"]
    pub const DLV: u16 = bindings::sldns_enum_rr_type_LDNS_RR_TYPE_DLV as u16;
}
