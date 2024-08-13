use std::panic::{RefUnwindSafe, UnwindSafe};

use crate::{sys, ModuleExtState};

#[macro_export]
macro_rules! set_module {
    ($mod:ty) => {
        use unbound::ctor::ctor;
        #[ctor]
        fn _internal_module_setup() {
            unbound::module::set_unbound_mod::<$mod>();
        }
    };
}

pub trait UnboundMod: Send + Sync + Sized + RefUnwindSafe + UnwindSafe {
    type EnvData;
    type QstateData;
    #[allow(clippy::result_unit_err)]
    fn init(_env: &mut crate::ModuleEnvMut<Self::EnvData>) -> Result<Self, ()> {
        Err(())
    }
    fn deinit(self, _env: &mut crate::ModuleEnvMut<Self::EnvData>) {}
    fn operate(
        &self,
        _qstate: &mut crate::ModuleQstateMut<Self::QstateData>,
        _event: crate::ModuleEvent,
        _entry: Option<&mut crate::OutboundEntryMut>,
    ) -> Option<ModuleExtState> {
        Some(ModuleExtState::Finished)
    }
    fn inform_super(
        &self,
        _qstate: &mut crate::ModuleQstateMut<Self::QstateData>,
        _super_qstate: &mut crate::ModuleQstateMut<::std::ffi::c_void>,
    ) {
    }
    fn clear(&self, _qstate: &mut crate::ModuleQstateMut<Self::QstateData>) {}

    fn get_mem(&self, _env: &mut crate::ModuleEnvMut<Self::EnvData>) -> usize {
        0
    }
}

/// # Safety
///
/// Be safe
pub(crate) unsafe trait SealedUnboundMod: Send + Sync {
    unsafe fn internal_deinit(
        self: Box<Self>,
        env: *mut sys::module_env,
        id: ::std::os::raw::c_int,
    );
    unsafe fn internal_operate(
        &self,
        qstate: *mut sys::module_qstate,
        event: sys::module_ev,
        id: ::std::os::raw::c_int,
        entry: *mut sys::outbound_entry,
    );
    unsafe fn internal_inform_super(
        &self,
        qstate: *mut sys::module_qstate,
        id: ::std::os::raw::c_int,
        super_qstate: *mut sys::module_qstate,
    );
    unsafe fn internal_clear(&self, qstate: *mut sys::module_qstate, id: ::std::os::raw::c_int);
    unsafe fn internal_get_mem(
        &self,
        env: *mut sys::module_env,
        id: ::std::os::raw::c_int,
    ) -> usize;
}

unsafe impl<T: UnboundMod> SealedUnboundMod for T {
    unsafe fn internal_deinit(
        self: Box<Self>,
        env: *mut sys::module_env,
        id: ::std::os::raw::c_int,
    ) {
        std::panic::catch_unwind(|| {
            self.deinit(&mut crate::ModuleEnvMut::from_raw(env, id).unwrap());
        })
        .unwrap_or(());
    }
    unsafe fn internal_operate(
        &self,
        qstate: *mut sys::module_qstate,
        event: sys::module_ev,
        id: ::std::os::raw::c_int,
        entry: *mut sys::outbound_entry,
    ) {
        std::panic::catch_unwind(|| {
            if let Some(ext_state) = self.operate(
                &mut crate::ModuleQstateMut::from_raw(qstate, id).unwrap(),
                event.into(),
                crate::OutboundEntryMut::from_raw(entry).as_mut(),
            ) {
                if let Some(id) = crate::check_id(id) {
                    (*qstate).ext_state[id] = ext_state as sys::module_ext_state;
                }
            }
        })
        .unwrap_or(());
    }
    unsafe fn internal_inform_super(
        &self,
        qstate: *mut sys::module_qstate,
        id: ::std::os::raw::c_int,
        super_qstate: *mut sys::module_qstate,
    ) {
        std::panic::catch_unwind(|| {
            self.inform_super(
                &mut crate::ModuleQstateMut::from_raw(qstate, id).unwrap(),
                &mut crate::ModuleQstateMut::from_raw(super_qstate, -1).unwrap(),
            );
        })
        .unwrap_or(());
    }
    unsafe fn internal_clear(&self, qstate: *mut sys::module_qstate, id: ::std::os::raw::c_int) {
        std::panic::catch_unwind(|| {
            self.clear(&mut crate::ModuleQstateMut::from_raw(qstate, id).unwrap());
        })
        .unwrap_or(());
    }
    unsafe fn internal_get_mem(
        &self,
        env: *mut sys::module_env,
        id: ::std::os::raw::c_int,
    ) -> usize {
        std::panic::catch_unwind(|| {
            self.get_mem(&mut crate::ModuleEnvMut::from_raw(env, id).unwrap())
        })
        .unwrap_or(0)
    }
}

pub(crate) static mut MODULE: std::sync::OnceLock<Box<dyn SealedUnboundMod>> =
    std::sync::OnceLock::new();
pub(crate) unsafe fn module() -> Option<&'static dyn SealedUnboundMod> {
    MODULE.get().map(|x| &**x)
}

pub(crate) static mut MODULE_FACTORY: std::sync::OnceLock<
    Box<
        dyn Sync
            + Send
            + FnOnce(*mut sys::module_env, ::std::os::raw::c_int) -> ::std::os::raw::c_int,
    >,
> = std::sync::OnceLock::new();

#[doc(hidden)]
pub fn set_unbound_mod<T: 'static + UnboundMod>() {
    unsafe {
        MODULE_FACTORY
            .set(Box::new(|env, id| {
                std::panic::catch_unwind(|| {
                    crate::ModuleEnvMut::from_raw(env, id)
                        .and_then(|mut env| T::init(&mut env).ok())
                        .map_or(0, |module| {
                            MODULE.set(Box::new(module)).map_err(|_| ()).unwrap();
                            1
                        })
                })
                .unwrap_or(0)
            }))
            .map_err(|_| "set_unbound_mod failed")
            .unwrap();
    }
}
