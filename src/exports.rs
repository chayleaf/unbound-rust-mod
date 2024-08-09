use crate::bindings::{module_env, module_ev, module_qstate, outbound_entry};

/// Initialize module internals, like database etc.
/// Called just once on module load.
///
/// # Arguments
///
/// - `env` - module environment
/// - `id` - module identifier
///
/// # Returns
///
/// Returns 1 or 0 (success or failure)
#[no_mangle]
pub unsafe extern "C" fn init(
    env: *mut module_env,
    id: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    if let Some(fac) = crate::MODULE_FACTORY.take() {
        fac(env, id)
    } else {
        0
    }
}

/// Deinitialize module internals.
/// Called just once on module unload.
#[no_mangle]
pub unsafe extern "C" fn deinit(env: *mut module_env, id: ::std::os::raw::c_int) {
    if let Some(module) = crate::MODULE.take() {
        module.internal_deinit(env, id);
    }
}

/// Perform action on pending query. Accepts a new query, or work on pending query.
/// You have to set qstate.ext_state on exit.
/// The state informs unbound about result and controls the following states.
///
/// # Arguments
///
/// - `qstate` - query state structure
/// - `event` - event type
/// - `id` - module identifier
/// - `entry` - outbound list entry (only used by the iterator module in unbound)
#[no_mangle]
pub unsafe extern "C" fn operate(
    qstate: *mut module_qstate,
    event: module_ev,
    id: ::std::os::raw::c_int,
    entry: *mut outbound_entry,
) {
    if let Some(module) = crate::module() {
        module.internal_operate(qstate, event, id, entry)
    }
}

/// Inform super querystate about the results from this subquerystate.
/// Is called when the querystate is finished.
///
/// # Arguments
///
/// - `qstate` - query state
/// - `id` - module identifier
/// - `super_qstate` - mesh state
#[no_mangle]
pub unsafe extern "C" fn inform_super(
    qstate: *mut module_qstate,
    id: ::std::os::raw::c_int,
    super_qstate: *mut module_qstate,
) {
    if let Some(module) = crate::module() {
        module.internal_inform_super(qstate, id, super_qstate)
    }
}

/// Clear is called once a query is complete and the response has been sent
/// back. It is used to clear up any per-query allocations.
#[no_mangle]
pub unsafe extern "C" fn clear(qstate: *mut module_qstate, id: ::std::os::raw::c_int) {
    if let Some(module) = crate::module() {
        module.internal_clear(qstate, id)
    }
}

/// Get mem is called when Unbound is printing performance information. This
/// only happens explicitly and is only used to show memory usage to the user.
#[no_mangle]
pub unsafe extern "C" fn get_mem(env: *mut module_env, id: ::std::os::raw::c_int) -> usize {
    crate::module()
        .map(|module| module.internal_get_mem(env, id))
        .unwrap_or(0)
}

// function interface assertions
const _INIT: crate::bindings::func_init_t = Some(init);
const _DEINIT: crate::bindings::func_deinit_t = Some(deinit);
const _OPERATE: crate::bindings::func_operate_t = Some(operate);
const _INFORM: crate::bindings::func_inform_t = Some(inform_super);
const _CLEAR: crate::bindings::func_clear_t = Some(clear);
const _GET_MEM: crate::bindings::func_get_mem_t = Some(get_mem);
