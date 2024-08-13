#![allow(clippy::type_complexity)]
use std::panic::{RefUnwindSafe, UnwindSafe};

use unbound::ModuleExtState;
#[allow(
    dead_code,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_imports,
    clippy::all,
    clippy::nursery,
    clippy::pedantic
)]
mod bindings;
mod combine;
#[cfg(feature = "example")]
mod example;
mod exports;
mod unbound;

pub trait UnboundMod: Send + Sync + Sized + RefUnwindSafe + UnwindSafe {
    type EnvData;
    type QstateData;
    #[allow(clippy::result_unit_err)]
    fn init(_env: &mut unbound::ModuleEnvMut<Self::EnvData>) -> Result<Self, ()> {
        Err(())
    }
    fn deinit(self, _env: &mut unbound::ModuleEnvMut<Self::EnvData>) {}
    fn operate(
        &self,
        _qstate: &mut unbound::ModuleQstateMut<Self::QstateData>,
        _event: unbound::ModuleEvent,
        _entry: Option<&mut unbound::OutboundEntryMut>,
    ) -> Option<ModuleExtState> {
        Some(ModuleExtState::Finished)
    }
    fn inform_super(
        &self,
        _qstate: &mut unbound::ModuleQstateMut<Self::QstateData>,
        _super_qstate: &mut unbound::ModuleQstateMut<::std::ffi::c_void>,
    ) {
    }
    fn clear(&self, _qstate: &mut unbound::ModuleQstateMut<Self::QstateData>) {}

    fn get_mem(&self, _env: &mut unbound::ModuleEnvMut<Self::EnvData>) -> usize {
        0
    }
}

/// # Safety
///
/// Be safe
unsafe trait SealedUnboundMod: Send + Sync {
    unsafe fn internal_deinit(
        self: Box<Self>,
        env: *mut bindings::module_env,
        id: ::std::os::raw::c_int,
    );
    unsafe fn internal_operate(
        &self,
        qstate: *mut bindings::module_qstate,
        event: bindings::module_ev,
        id: ::std::os::raw::c_int,
        entry: *mut bindings::outbound_entry,
    );
    unsafe fn internal_inform_super(
        &self,
        qstate: *mut bindings::module_qstate,
        id: ::std::os::raw::c_int,
        super_qstate: *mut bindings::module_qstate,
    );
    unsafe fn internal_clear(
        &self,
        qstate: *mut bindings::module_qstate,
        id: ::std::os::raw::c_int,
    );
    unsafe fn internal_get_mem(
        &self,
        env: *mut bindings::module_env,
        id: ::std::os::raw::c_int,
    ) -> usize;
}

unsafe impl<T: UnboundMod> SealedUnboundMod for T {
    unsafe fn internal_deinit(
        self: Box<Self>,
        env: *mut bindings::module_env,
        id: ::std::os::raw::c_int,
    ) {
        std::panic::catch_unwind(|| {
            self.deinit(&mut unbound::ModuleEnvMut::from_raw(env, id).unwrap());
        })
        .unwrap_or(());
    }
    unsafe fn internal_operate(
        &self,
        qstate: *mut bindings::module_qstate,
        event: bindings::module_ev,
        id: ::std::os::raw::c_int,
        entry: *mut bindings::outbound_entry,
    ) {
        std::panic::catch_unwind(|| {
            if let Some(ext_state) = self.operate(
                &mut unbound::ModuleQstateMut::from_raw(qstate, id).unwrap(),
                event.into(),
                unbound::OutboundEntryMut::from_raw(entry).as_mut(),
            ) {
                if let Some(id) = unbound::check_id(id) {
                    (*qstate).ext_state[id] = ext_state as bindings::module_ext_state;
                }
            }
        })
        .unwrap_or(());
    }
    unsafe fn internal_inform_super(
        &self,
        qstate: *mut bindings::module_qstate,
        id: ::std::os::raw::c_int,
        super_qstate: *mut bindings::module_qstate,
    ) {
        std::panic::catch_unwind(|| {
            self.inform_super(
                &mut unbound::ModuleQstateMut::from_raw(qstate, id).unwrap(),
                &mut unbound::ModuleQstateMut::from_raw(super_qstate, -1).unwrap(),
            );
        })
        .unwrap_or(());
    }
    unsafe fn internal_clear(
        &self,
        qstate: *mut bindings::module_qstate,
        id: ::std::os::raw::c_int,
    ) {
        std::panic::catch_unwind(|| {
            self.clear(&mut unbound::ModuleQstateMut::from_raw(qstate, id).unwrap());
        })
        .unwrap_or(());
    }
    unsafe fn internal_get_mem(
        &self,
        env: *mut bindings::module_env,
        id: ::std::os::raw::c_int,
    ) -> usize {
        std::panic::catch_unwind(|| {
            self.get_mem(&mut unbound::ModuleEnvMut::from_raw(env, id).unwrap())
        })
        .unwrap_or(0)
    }
}

static mut MODULE: std::sync::OnceLock<Box<dyn SealedUnboundMod>> = std::sync::OnceLock::new();
unsafe fn module() -> Option<&'static dyn SealedUnboundMod> {
    MODULE.get().map(|x| &**x)
}

static mut MODULE_FACTORY: std::sync::OnceLock<
    Box<
        dyn Sync
            + Send
            + FnOnce(*mut bindings::module_env, ::std::os::raw::c_int) -> ::std::os::raw::c_int,
    >,
> = std::sync::OnceLock::new();
pub fn set_unbound_mod<T: 'static + UnboundMod>() {
    unsafe {
        MODULE_FACTORY
            .set(Box::new(|env, id| {
                std::panic::catch_unwind(|| {
                    unbound::ModuleEnvMut::from_raw(env, id)
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
