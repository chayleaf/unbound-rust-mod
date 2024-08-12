#![allow(dead_code)]
use crate::bindings::{
    self, config_file, dns_msg, in6_addr, in6_addr__bindgen_ty_1, in_addr, infra_cache, key_cache,
    lruhash_entry, module_env, module_ev, module_ext_state, module_qstate, outbound_entry,
    packed_rrset_data, packed_rrset_key, query_info, reply_info, rrset_cache, rrset_id_type,
    rrset_trust, sec_status, slabhash, sldns_enum_ede_code, sockaddr_in, sockaddr_in6,
    sockaddr_storage, ub_packed_rrset_key, AF_INET, AF_INET6,
};
use std::{ffi::CStr, marker::PhantomData, net::SocketAddr, os::raw::c_char, ptr, time::Duration};

pub struct ConfigFileMut<'a>(
    pub(crate) *mut config_file,
    PhantomData<&'a mut config_file>,
);
pub struct SlabHashMut<'a>(pub(crate) *mut slabhash, PhantomData<&'a mut slabhash>);
pub struct RrsetCacheMut<'a>(
    pub(crate) *mut rrset_cache,
    PhantomData<&'a mut rrset_cache>,
);
pub struct InfraCacheMut<'a>(
    pub(crate) *mut infra_cache,
    PhantomData<&'a mut infra_cache>,
);
pub struct KeyCacheMut<'a>(pub(crate) *mut key_cache, PhantomData<&'a mut key_cache>);
pub struct ModuleEnv<T>(
    pub(crate) *mut module_env,
    pub(crate) std::ffi::c_int,
    pub(crate) PhantomData<T>,
);
pub struct ModuleQstate<'a, T>(
    pub(crate) *mut module_qstate,
    pub(crate) std::ffi::c_int,
    pub(crate) PhantomData<&'a mut T>,
);
pub struct OutboundEntryMut<'a>(
    pub(crate) *mut outbound_entry,
    pub(crate) PhantomData<&'a mut outbound_entry>,
);
pub struct QueryInfoMut<'a>(
    pub(crate) *mut query_info,
    pub(crate) PhantomData<&'a mut query_info>,
);
pub struct DnsMsgMut<'a>(
    pub(crate) *mut dns_msg,
    pub(crate) PhantomData<&'a mut dns_msg>,
);
pub struct ReplyInfo<'a>(
    pub(crate) *mut reply_info,
    pub(crate) PhantomData<&'a mut reply_info>,
);
pub struct UbPackedRrsetKey<'a>(
    pub(crate) *mut ub_packed_rrset_key,
    pub(crate) PhantomData<&'a mut ub_packed_rrset_key>,
);
pub struct LruHashEntry<'a>(
    pub(crate) *mut lruhash_entry,
    pub(crate) PhantomData<&'a mut lruhash_entry>,
);
pub struct PackedRrsetKey<'a>(
    pub(crate) *mut packed_rrset_key,
    pub(crate) PhantomData<&'a mut packed_rrset_key>,
);
pub struct PackedRrsetData<'a>(
    pub(crate) *mut packed_rrset_data,
    pub(crate) PhantomData<&'a mut packed_rrset_data>,
);

impl<'a> QueryInfoMut<'a> {
    pub fn qname(&self) -> &CStr {
        unsafe { CStr::from_ptr((*self.0).qname as *const c_char) }
    }
    pub fn qtype(&self) -> u16 {
        unsafe { (*self.0).qtype }
    }
    pub fn qclass(&self) -> u16 {
        unsafe { (*self.0).qclass }
    }
}

impl<T> ModuleEnv<T> {
    pub fn config_file_mut(&mut self) -> ConfigFileMut<'_> {
        ConfigFileMut(unsafe { (*self.0).cfg }, Default::default())
    }
    pub fn msg_cache_mut(&mut self) -> SlabHashMut<'_> {
        SlabHashMut(unsafe { (*self.0).msg_cache }, Default::default())
    }
    pub fn rrset_cache_mut(&mut self) -> RrsetCacheMut<'_> {
        RrsetCacheMut(unsafe { (*self.0).rrset_cache }, Default::default())
    }
    pub fn infra_cache_mut(&mut self) -> InfraCacheMut<'_> {
        InfraCacheMut(unsafe { (*self.0).infra_cache }, Default::default())
    }
    pub fn key_cache_mut(&mut self) -> KeyCacheMut<'_> {
        KeyCacheMut(unsafe { (*self.0).key_cache }, Default::default())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn send_query<Y>(
        &mut self,
        qinfo: &QueryInfoMut,
        flags: u16,
        dnssec: u32,
        want_dnssec: bool,
        nocaps: bool,
        check_ratelimit: bool,
        addr: SocketAddr,
        zone: &[u8],
        tcp_upstream: bool,
        ssl_upstream: bool,
        tls_auth_name: Option<&CStr>,
        q: &mut ModuleQstate<Y>,
    ) -> (Option<OutboundEntryMut<'_>>, bool) {
        let mut was_ratelimited = 0;
        let ret = unsafe {
            let mut addr4 = sockaddr_in {
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0u8; 8],
                sin_family: AF_INET as u16,
            };
            let mut addr6 = sockaddr_in6 {
                sin6_port: 0,
                sin6_addr: in6_addr {
                    __in6_u: in6_addr__bindgen_ty_1 {
                        __u6_addr8: [0u8; 16],
                    },
                },
                sin6_family: AF_INET6 as u16,
                sin6_flowinfo: 0,
                sin6_scope_id: 0,
            };
            let (addr, addr_len) = match addr {
                SocketAddr::V4(x) => {
                    addr4.sin_port = x.port();
                    addr4.sin_addr.s_addr = (*x.ip()).into();
                    (
                        &addr4 as *const _ as *const sockaddr_storage,
                        std::mem::size_of_val(&addr4),
                    )
                }
                SocketAddr::V6(x) => {
                    addr6.sin6_addr.__in6_u.__u6_addr8 = x.ip().octets();
                    addr6.sin6_flowinfo = x.flowinfo();
                    addr6.sin6_scope_id = x.scope_id();
                    (
                        &addr6 as *const _ as *const sockaddr_storage,
                        std::mem::size_of_val(&addr6),
                    )
                }
            };
            ((*self.0).send_query.unwrap_unchecked())(
                &qinfo.0 as *const _ as *mut _,
                flags,
                dnssec as i32,
                want_dnssec.into(),
                nocaps.into(),
                check_ratelimit.into(),
                addr as *mut _,
                addr_len as u32,
                zone.as_ptr() as *mut _,
                zone.len(),
                tcp_upstream.into(),
                ssl_upstream.into(),
                tls_auth_name
                    .map(|x| x.as_ptr() as *mut _)
                    .unwrap_or(ptr::null_mut()),
                q.0,
                &mut was_ratelimited as *mut _,
            )
        };
        if ret.is_null() {
            (None, was_ratelimited != 0)
        } else {
            (
                Some(OutboundEntryMut(ret, Default::default())),
                was_ratelimited != 0,
            )
        }
    }
    pub fn detach_subs<Y>(&mut self, qstate: &mut ModuleQstate<Y>) {
        unsafe { (*self.0).detach_subs.unwrap_unchecked()(qstate.0) }
    }
    unsafe fn attach_sub<Y>(
        &mut self,
        qstate: &mut ModuleQstate<Y>,
        qinfo: &QueryInfoMut,
        qflags: u16,
        prime: bool,
        valrec: bool,
        init_sub: impl FnOnce(*mut module_qstate) -> Result<(), ()>,
    ) -> Result<Option<ModuleQstate<'_, ()>>, ()> {
        let mut newq: *mut module_qstate = ptr::null_mut();
        let res = unsafe {
            ((*self.0).attach_sub.unwrap_unchecked())(
                qstate.0,
                &qinfo.0 as *const _ as *mut _,
                qflags,
                prime.into(),
                valrec.into(),
                &mut newq as _,
            )
        };
        if res != 0 {
            Ok(if newq.is_null() {
                None
            } else if init_sub(newq).is_ok() {
                Some(ModuleQstate(newq, qstate.1, Default::default()))
            } else {
                unsafe { ((*self.0).kill_sub.unwrap_unchecked())(newq) }
                return Err(());
            })
        } else {
            Err(())
        }
    }
    // add_sub: TODO similar to above
    // detect_cycle: TODO
    // (note that &mut T is wrapped in dynmod stuff)
    // fn modinfo_mut(&mut self) -> Option<&mut T> {}
}

impl<T> ModuleQstate<'_, T> {
    pub fn qinfo_mut(&mut self) -> QueryInfoMut<'_> {
        QueryInfoMut(
            unsafe { &mut (*self.0).qinfo as *mut query_info },
            Default::default(),
        )
    }
    pub fn return_msg_mut(&mut self) -> Option<DnsMsgMut<'_>> {
        if unsafe { (*self.0).return_msg.is_null() } {
            None
        } else {
            Some(DnsMsgMut(
                unsafe { (*self.0).return_msg },
                Default::default(),
            ))
        }
    }
    pub fn set_ext_state(&mut self, state: ModuleExtState) {
        unsafe {
            (*self.0).ext_state[self.1 as usize] = state as module_ext_state;
        }
    }
}

impl DnsMsgMut<'_> {
    pub fn rep(&self) -> Option<ReplyInfo<'_>> {
        if unsafe { (*self.0).rep.is_null() } {
            None
        } else {
            Some(ReplyInfo(unsafe { (*self.0).rep }, Default::default()))
        }
    }
}

impl ReplyInfo<'_> {
    pub fn flags(&self) -> u16 {
        unsafe { (*self.0).flags }
    }
    pub fn authoritative(&self) -> bool {
        unsafe { (*self.0).authoritative != 0 }
    }
    pub fn qdcount(&self) -> u8 {
        unsafe { (*self.0).qdcount }
    }
    pub fn padding(&self) -> u32 {
        unsafe { (*self.0).padding }
    }
    pub fn ttl(&self) -> Option<Duration> {
        (unsafe { (*self.0).ttl })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn prefetch_ttl(&self) -> Option<Duration> {
        (unsafe { (*self.0).prefetch_ttl })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn serve_expired_ttl(&self) -> Option<Duration> {
        (unsafe { (*self.0).serve_expired_ttl })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn security(&self) -> SecStatus {
        SecStatus::from(unsafe { (*self.0).security })
    }
    pub fn reason_bogus(&self) -> SldnsEdeCode {
        SldnsEdeCode::from(unsafe { (*self.0).reason_bogus })
    }
    pub fn reason_bogus_str(&self) -> Option<&CStr> {
        if unsafe { (*self.0).reason_bogus_str.is_null() } {
            None
        } else {
            Some(unsafe { CStr::from_ptr((*self.0).reason_bogus_str) })
        }
    }
    pub fn an_numrrsets(&self) -> usize {
        unsafe { (*self.0).an_numrrsets }
    }
    pub fn ns_numrrsets(&self) -> usize {
        unsafe { (*self.0).ns_numrrsets }
    }
    pub fn ar_numrrsets(&self) -> usize {
        unsafe { (*self.0).ar_numrrsets }
    }
    pub fn rrset_count(&self) -> usize {
        unsafe { (*self.0).rrset_count }
    }
    pub fn rrsets(&self) -> impl '_ + Iterator<Item = UbPackedRrsetKey<'_>> {
        let total = self.rrset_count();
        let rrsets = unsafe { (*self.0).rrsets };
        (0..total).map(move |i| UbPackedRrsetKey(unsafe { *rrsets.add(i) }, Default::default()))
    }
}

impl UbPackedRrsetKey<'_> {
    pub fn entry(&self) -> LruHashEntry<'_> {
        LruHashEntry(
            unsafe { &mut (*self.0).entry as *mut _ },
            Default::default(),
        )
    }
    pub fn id(&self) -> RrsetIdType {
        unsafe { (*self.0).id }
    }
    pub fn rk(&self) -> PackedRrsetKey<'_> {
        PackedRrsetKey(unsafe { &mut (*self.0).rk as *mut _ }, Default::default())
    }
}

impl PackedRrsetKey<'_> {
    pub fn dname(&self) -> Option<&'_ CStr> {
        if unsafe { (*self.0).dname.is_null() } {
            None
        } else {
            Some(unsafe { CStr::from_ptr((*self.0).dname as *const c_char) })
        }
    }
    pub fn flags(&self) -> u32 {
        unsafe { (*self.0).flags }
    }
    pub fn type_(&self) -> u16 {
        u16::from_be(unsafe { (*self.0).type_ })
    }
    pub fn rrset_class(&self) -> u16 {
        u16::from_be(unsafe { (*self.0).rrset_class })
    }
}

impl LruHashEntry<'_> {
    pub fn data(&self) -> PackedRrsetData<'_> {
        // FIXME: shouldnt pthread lock be used here?
        unsafe { PackedRrsetData((*self.0).data as *mut packed_rrset_data, Default::default()) }
    }
}

impl PackedRrsetData<'_> {
    pub fn ttl_add(&self) -> Option<Duration> {
        (unsafe { (*self.0).ttl_add })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn ttl(&self) -> Option<Duration> {
        (unsafe { (*self.0).ttl })
            .try_into()
            .map(Duration::from_secs)
            .ok()
    }
    pub fn count(&self) -> usize {
        unsafe { (*self.0).count }
    }
    pub fn rrsig_count(&self) -> usize {
        unsafe { (*self.0).rrsig_count }
    }
    pub fn trust(&self) -> RrsetTrust {
        RrsetTrust::from(unsafe { (*self.0).trust })
    }
    pub fn security(&self) -> SecStatus {
        SecStatus::from(unsafe { (*self.0).security })
    }
    pub fn rr_data(&self) -> impl '_ + Iterator<Item = (&[u8], Option<Duration>)> {
        let total = self.count();
        let ttl = unsafe { (*self.0).rr_ttl };
        let len = unsafe { (*self.0).rr_len };
        let data = unsafe { (*self.0).rr_data };
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
        let len = unsafe { (*self.0).rr_len };
        let data = unsafe { (*self.0).rr_data };
        (total..total + total2)
            .map(move |i| unsafe { std::slice::from_raw_parts(*data.add(i), *len.add(i)) })
    }
}

type RrsetIdType = rrset_id_type;

#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ModuleEvent {
    /// new query
    New = 0,
    /// query passed by other module
    Pass = 1,
    /// reply inbound from server
    Reply = 2,
    /// no reply, timeout or other error
    NoReply = 3,
    /// reply is there, but capitalisation check failed
    CapsFail = 4,
    /// next module is done, and its reply is awaiting you
    ModDone = 5,
    /// error
    Error = 6,
    Unknown = 7,
}

impl From<module_ev> for ModuleEvent {
    fn from(value: module_ev) -> Self {
        match value {
            0 => Self::New,
            1 => Self::Pass,
            2 => Self::Reply,
            3 => Self::NoReply,
            4 => Self::CapsFail,
            5 => Self::ModDone,
            6 => Self::Error,
            _ => Self::Unknown,
        }
    }
}

#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SecStatus {
    /// UNCHECKED means that object has yet to be validated.
    Unchecked = bindings::sec_status_sec_status_unchecked,
    /// BOGUS means that the object (RRset or message) failed to validate\n  (according to local policy), but should have validated.
    Bogus = bindings::sec_status_sec_status_bogus,
    /// INDETERMINATE means that the object is insecure, but not\n authoritatively so. Generally this means that the RRset is not\n below a configured trust anchor.
    Indeterminate = bindings::sec_status_sec_status_indeterminate,
    /// INSECURE means that the object is authoritatively known to be\n insecure. Generally this means that this RRset is below a trust\n anchor, but also below a verified, insecure delegation.
    Insecure = bindings::sec_status_sec_status_insecure,
    /// SECURE_SENTINEL_FAIL means that the object (RRset or message)\n validated according to local policy but did not succeed in the root\n KSK sentinel test (draft-ietf-dnsop-kskroll-sentinel).
    SecureSentinelFail = bindings::sec_status_sec_status_secure_sentinel_fail,
    /// SECURE means that the object (RRset or message) validated\n according to local policy.
    Secure = bindings::sec_status_sec_status_secure,
    Unknown = 99,
}

impl From<sec_status> for SecStatus {
    fn from(value: module_ev) -> Self {
        match value {
            bindings::sec_status_sec_status_unchecked => Self::Unchecked,
            bindings::sec_status_sec_status_bogus => Self::Bogus,
            bindings::sec_status_sec_status_indeterminate => Self::Indeterminate,
            bindings::sec_status_sec_status_insecure => Self::Insecure,
            bindings::sec_status_sec_status_secure_sentinel_fail => Self::SecureSentinelFail,
            bindings::sec_status_sec_status_secure => Self::Secure,
            _ => Self::Unknown,
        }
    }
}

#[non_exhaustive]
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SldnsEdeCode {
    None = -1,
    Other = 0,
    UnsupportedDnskeyAlg = 1,
    UnsupportedDsDigest = 2,
    StaleAnswer = 3,
    ForgedAnswer = 4,
    DnssecIndeterminate = 5,
    DnssecBogus = 6,
    SignatureExpired = 7,
    SignatureNotYetValid = 8,
    DnskeyMissing = 9,
    RrsigsMissing = 10,
    NoZoneKeyBitSet = 11,
    NsecMissing = 12,
    CachedError = 13,
    NotReady = 14,
    Blocked = 15,
    Censored = 16,
    Filtered = 17,
    Prohibited = 18,
    StaleNxdomainAnswer = 19,
    NotAuthoritative = 20,
    NotSupported = 21,
    NoReachableAuthority = 22,
    NetworkError = 23,
    InvalidData = 24,
}

impl From<sldns_enum_ede_code> for SldnsEdeCode {
    fn from(value: sldns_enum_ede_code) -> Self {
        match value {
            -1 => Self::None,
            0 => Self::Other,
            1 => Self::UnsupportedDnskeyAlg,
            2 => Self::UnsupportedDsDigest,
            3 => Self::StaleAnswer,
            4 => Self::ForgedAnswer,
            5 => Self::DnssecIndeterminate,
            6 => Self::DnssecBogus,
            7 => Self::SignatureExpired,
            8 => Self::SignatureNotYetValid,
            9 => Self::DnskeyMissing,
            10 => Self::RrsigsMissing,
            11 => Self::NoZoneKeyBitSet,
            12 => Self::NsecMissing,
            13 => Self::CachedError,
            14 => Self::NotReady,
            15 => Self::Blocked,
            16 => Self::Censored,
            17 => Self::Filtered,
            18 => Self::Prohibited,
            19 => Self::StaleNxdomainAnswer,
            20 => Self::NotAuthoritative,
            21 => Self::NotSupported,
            22 => Self::NoReachableAuthority,
            23 => Self::NetworkError,
            24 => Self::InvalidData,
            _ => Self::Other,
        }
    }
}

#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum RrsetTrust {
    /// Initial value for trust
    None = bindings::rrset_trust_rrset_trust_none,
    /// Additional information from non-authoritative answers
    AddNoAa = bindings::rrset_trust_rrset_trust_add_noAA,
    /// Data from the authority section of a non-authoritative answer
    AuthNoAa = bindings::rrset_trust_rrset_trust_auth_noAA,
    /// Additional information from an authoritative answer
    AddAa = bindings::rrset_trust_rrset_trust_add_AA,
    /// non-authoritative data from the answer section of authoritative answers
    NonauthAnsAa = bindings::rrset_trust_rrset_trust_nonauth_ans_AA,
    /// Data from the answer section of a non-authoritative answer
    AnsNoAa = bindings::rrset_trust_rrset_trust_ans_noAA,
    /// Glue from a primary zone, or glue from a zone transfer
    Glue = bindings::rrset_trust_rrset_trust_glue,
    /// Data from the authority section of an authoritative answer
    AuthAa = bindings::rrset_trust_rrset_trust_auth_AA,
    /// The authoritative data included in the answer section of an\n  authoritative reply
    AnsAa = bindings::rrset_trust_rrset_trust_ans_AA,
    /// Data from a zone transfer, other than glue
    SecNoglue = bindings::rrset_trust_rrset_trust_sec_noglue,
    /// Data from a primary zone file, other than glue data
    PrimNoglue = bindings::rrset_trust_rrset_trust_prim_noglue,
    /// DNSSEC(rfc4034) validated with trusted keys
    Validated = bindings::rrset_trust_rrset_trust_validated,
    /// Ultimately trusted, no more trust is possible,
    /// trusted keys from the unbound configuration setup.
    Ultimate = bindings::rrset_trust_rrset_trust_ultimate,
    Unknown = 99,
}

impl From<rrset_trust> for RrsetTrust {
    fn from(value: rrset_trust) -> Self {
        match value {
            bindings::rrset_trust_rrset_trust_none => Self::None,
            bindings::rrset_trust_rrset_trust_add_noAA => Self::AddNoAa,
            bindings::rrset_trust_rrset_trust_auth_noAA => Self::AuthNoAa,
            bindings::rrset_trust_rrset_trust_add_AA => Self::AddAa,
            bindings::rrset_trust_rrset_trust_nonauth_ans_AA => Self::NonauthAnsAa,
            bindings::rrset_trust_rrset_trust_ans_noAA => Self::AnsNoAa,
            bindings::rrset_trust_rrset_trust_glue => Self::Glue,
            bindings::rrset_trust_rrset_trust_auth_AA => Self::AuthAa,
            bindings::rrset_trust_rrset_trust_ans_AA => Self::AnsAa,
            bindings::rrset_trust_rrset_trust_sec_noglue => Self::SecNoglue,
            bindings::rrset_trust_rrset_trust_prim_noglue => Self::PrimNoglue,
            bindings::rrset_trust_rrset_trust_validated => Self::Validated,
            bindings::rrset_trust_rrset_trust_ultimate => Self::Ultimate,
            _ => Self::Unknown,
        }
    }
}

#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ModuleExtState {
    InitialState = bindings::module_ext_state_module_state_initial,
    WaitReply = bindings::module_ext_state_module_wait_reply,
    WaitModule = bindings::module_ext_state_module_wait_module,
    RestartNext = bindings::module_ext_state_module_restart_next,
    WaitSubquery = bindings::module_ext_state_module_wait_subquery,
    Error = bindings::module_ext_state_module_error,
    Finished = bindings::module_ext_state_module_finished,
    Unknown = 99,
}

impl ModuleExtState {
    pub(crate) fn importance(&self) -> usize {
        match *self {
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

impl From<module_ext_state> for ModuleExtState {
    fn from(value: module_ext_state) -> Self {
        match value {
            bindings::module_ext_state_module_state_initial => Self::InitialState,
            bindings::module_ext_state_module_wait_reply => Self::WaitReply,
            bindings::module_ext_state_module_wait_module => Self::WaitModule,
            bindings::module_ext_state_module_restart_next => Self::RestartNext,
            bindings::module_ext_state_module_wait_subquery => Self::WaitSubquery,
            bindings::module_ext_state_module_error => Self::Error,
            bindings::module_ext_state_module_finished => Self::Finished,
            _ => Self::Unknown,
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
    pub const A: u16 = 1;
    /// An authoritative name server
    pub const NS: u16 = 2;
    /// A mail destination (Obsolete - use MX)
    pub const MD: u16 = 3;
    /// A mail forwarder (Obsolete - use MX)
    pub const MF: u16 = 4;
    /// The canonical name for an alias
    pub const CNAME: u16 = 5;
    /// Marks the start of a zone of authority
    pub const SOA: u16 = 6;
    /// A mailbox domain name (EXPERIMENTAL)
    pub const MB: u16 = 7;
    /// A mail group member (EXPERIMENTAL)
    pub const MG: u16 = 8;
    /// A mail rename domain name (EXPERIMENTAL)
    pub const MR: u16 = 9;
    /// A null RR (EXPERIMENTAL)
    pub const NULL: u16 = 10;
    /// A well known service description
    pub const WKS: u16 = 11;
    /// A domain name pointer
    pub const PTR: u16 = 12;
    /// Host information
    pub const HINFO: u16 = 13;
    /// Mailbox or mail list information
    pub const MINFO: u16 = 14;
    /// Mail exchange
    pub const MX: u16 = 15;
    /// Text strings
    pub const TXT: u16 = 16;
    /// rFC1183
    pub const RP: u16 = 17;
    /// rFC1183
    pub const AFSDB: u16 = 18;
    /// rFC1183
    pub const X25: u16 = 19;
    /// rFC1183
    pub const ISDN: u16 = 20;
    /// rFC1183
    pub const RT: u16 = 21;
    /// rFC1706
    pub const NSAP: u16 = 22;
    /// rFC1348
    pub const NSAP_PTR: u16 = 23;
    /// 2535typecode
    pub const SIG: u16 = 24;
    /// 2535typecode
    pub const KEY: u16 = 25;
    /// rFC2163
    pub const PX: u16 = 26;
    /// rFC1712
    pub const GPOS: u16 = 27;
    /// Ipv6 address
    pub const AAAA: u16 = 28;
    /// lOC record  RFC1876
    pub const LOC: u16 = 29;
    /// 2535typecode
    pub const NXT: u16 = 30;
    /// Draft-ietf-nimrod-dns-01.txt
    pub const EID: u16 = 31;
    /// Draft-ietf-nimrod-dns-01.txt
    pub const NIMLOC: u16 = 32;
    /// sRV record RFC2782
    pub const SRV: u16 = 33;
    /// Http://www.jhsoft.com/rfc/af-saa-0069.000.rtf
    pub const ATMA: u16 = 34;
    /// rFC2915
    pub const NAPTR: u16 = 35;
    /// rFC2230
    pub const KX: u16 = 36;
    /// rFC2538
    pub const CERT: u16 = 37;
    /// rFC2874
    pub const A6: u16 = 38;
    /// rFC2672
    pub const DNAME: u16 = 39;
    /// Dnsind-kitchen-sink-02.txt
    pub const SINK: u16 = 40;
    /// pseudo OPT record...
    pub const OPT: u16 = 41;
    /// rFC3123
    pub const APL: u16 = 42;
    /// rFC4034, RFC3658
    pub const DS: u16 = 43;
    /// sSH Key Fingerprint
    pub const SSHFP: u16 = 44;
    /// iPsec Key
    pub const IPSECKEY: u16 = 45;
    /// dNSSEC
    pub const RRSIG: u16 = 46;
    /// dNSSEC
    pub const NSEC: u16 = 47;
    /// dNSSEC
    pub const DNSKEY: u16 = 48;
    /// dNSSEC
    pub const DHCID: u16 = 49;
    /// dNSSEC
    pub const NSEC3: u16 = 50;
    /// dNSSEC
    pub const NSEC3PARAM: u16 = 51;
    /// dNSSEC
    pub const NSEC3PARAMS: u16 = 51;
    /// dNSSEC
    pub const TLSA: u16 = 52;
    /// dNSSEC
    pub const SMIMEA: u16 = 53;
    /// dNSSEC
    pub const HIP: u16 = 55;
    ///draft-reid-dnsext-zs
    pub const NINFO: u16 = 56;
    ///draft-reid-dnsext-rkey
    pub const RKEY: u16 = 57;
    ///draft-ietf-dnsop-trust-history
    pub const TALINK: u16 = 58;
    ///draft-ietf-dnsop-trust-history
    pub const CDS: u16 = 59;
    ///RFC 7344
    pub const CDNSKEY: u16 = 60;
    ///RFC 7344
    pub const OPENPGPKEY: u16 = 61;
    ///RFC 7344
    pub const CSYNC: u16 = 62;
    ///RFC 7344
    pub const ZONEMD: u16 = 63;
    ///RFC 7344
    pub const SVCB: u16 = 64;
    ///RFC 7344
    pub const HTTPS: u16 = 65;
    ///RFC 7344
    pub const SPF: u16 = 99;
    ///RFC 7344
    pub const UINFO: u16 = 100;
    ///RFC 7344
    pub const UID: u16 = 101;
    ///RFC 7344
    pub const GID: u16 = 102;
    ///RFC 7344
    pub const UNSPEC: u16 = 103;
    ///RFC 7344
    pub const NID: u16 = 104;
    ///RFC 7344
    pub const L32: u16 = 105;
    ///RFC 7344
    pub const L64: u16 = 106;
    ///RFC 7344
    pub const LP: u16 = 107;
    ///draft-jabley-dnsext-eui48-eui64-rrtypes
    pub const EUI48: u16 = 108;
    ///draft-jabley-dnsext-eui48-eui64-rrtypes
    pub const EUI64: u16 = 109;
    ///draft-jabley-dnsext-eui48-eui64-rrtypes
    pub const TKEY: u16 = 249;
    ///draft-jabley-dnsext-eui48-eui64-rrtypes
    pub const TSIG: u16 = 250;
    ///draft-jabley-dnsext-eui48-eui64-rrtypes
    pub const IXFR: u16 = 251;
    ///draft-jabley-dnsext-eui48-eui64-rrtypes
    pub const AXFR: u16 = 252;
    /// a request for mailbox-related records (MB, MG or MR)
    pub const MAILB: u16 = 253;
    /// a request for mail agent RRs (Obsolete - see MX)
    pub const MAILA: u16 = 254;
    /// Any type (wildcard)
    pub const ANY: u16 = 255;
    pub const URI: u16 = 256;
    pub const CAA: u16 = 257;
    pub const AVC: u16 = 258;
    ///DNSSEC trust Authorities
    pub const TA: u16 = 32768;
    pub const DLV: u16 = 32769;
}
