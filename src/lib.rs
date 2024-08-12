use std::panic::{RefUnwindSafe, UnwindSafe};
#[allow(
    dead_code,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_imports
)]
mod bindings;
mod combine;
mod domain_tree;
#[cfg(feature = "example")]
mod example;
mod exports;
mod nftables;
mod unbound;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub trait UnboundMod: Send + Sync + Sized + RefUnwindSafe + UnwindSafe {
    type EnvData;
    type QstateData;
    #[allow(clippy::result_unit_err)]
    fn init(_env: &mut unbound::ModuleEnv<Self::EnvData>) -> Result<Self, ()> {
        Err(())
    }
    fn deinit(self, _env: &mut unbound::ModuleEnv<Self::EnvData>) {}
    fn operate(
        &self,
        _qstate: &mut unbound::ModuleQstate<Self::QstateData>,
        _event: unbound::ModuleEvent,
        _entry: &mut unbound::OutboundEntryMut,
    ) {
    }
    fn inform_super(
        &self,
        _qstate: &mut unbound::ModuleQstate<Self::QstateData>,
        _super_qstate: &mut unbound::ModuleQstate<::std::ffi::c_void>,
    ) {
    }
    fn clear(&self, _qstate: &mut unbound::ModuleQstate<Self::QstateData>) {}

    fn get_mem(&self, _env: &mut unbound::ModuleEnv<Self::EnvData>) -> usize {
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
            self.deinit(&mut unbound::ModuleEnv(env, id, Default::default()))
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
            self.operate(
                &mut unbound::ModuleQstate(qstate, id, Default::default()),
                event.into(),
                &mut unbound::OutboundEntryMut(entry, Default::default()),
            )
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
                &mut unbound::ModuleQstate(qstate, id, Default::default()),
                &mut unbound::ModuleQstate(super_qstate, -1, Default::default()),
            )
        })
        .unwrap_or(());
    }
    unsafe fn internal_clear(
        &self,
        qstate: *mut bindings::module_qstate,
        id: ::std::os::raw::c_int,
    ) {
        std::panic::catch_unwind(|| {
            self.clear(&mut unbound::ModuleQstate(qstate, id, Default::default()))
        })
        .unwrap_or(());
    }
    unsafe fn internal_get_mem(
        &self,
        env: *mut bindings::module_env,
        id: ::std::os::raw::c_int,
    ) -> usize {
        std::panic::catch_unwind(|| {
            self.get_mem(&mut unbound::ModuleEnv(env, id, Default::default()))
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
                    if let Ok(module) =
                        T::init(&mut unbound::ModuleEnv(env, id, Default::default()))
                    {
                        MODULE.set(Box::new(module)).map_err(|_| ()).unwrap();
                        1
                    } else {
                        0
                    }
                })
                .unwrap_or(0)
            }))
            .map_err(|_| "set_unbound_mod failed")
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
