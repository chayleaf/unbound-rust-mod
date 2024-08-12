use std::panic::{RefUnwindSafe, UnwindSafe};

use crate::unbound::ModuleExtState;
use crate::UnboundMod;

macro_rules! impl_tuple {
    ($($i:tt $t:tt),*) => {
        impl<A, $($t, )*> UnboundMod for (A, $($t, )*)
        where
            A: UnboundMod + UnwindSafe + RefUnwindSafe,
            $($t: UnboundMod<EnvData = A::EnvData, QstateData = A::QstateData>
                + UnwindSafe
                + RefUnwindSafe,)*
        {
            type EnvData = A::EnvData;
            type QstateData = A::QstateData;
            fn init(env: &mut crate::unbound::ModuleEnv<Self::EnvData>) -> Result<Self, ()> {
                Ok((A::init(env)?, $($t::init(env)?, )*))
            }
            fn clear(&self, qstate: &mut crate::unbound::ModuleQstate<Self::QstateData>) {
                self.0.clear(qstate);
                $(self.$i.clear(qstate);)*
            }
            fn deinit(self, env: &mut crate::unbound::ModuleEnv<Self::EnvData>) {
                self.0.deinit(env);
                $(self.$i.deinit(env);)*
            }
            fn operate(
                &self,
                qstate: &mut crate::unbound::ModuleQstate<Self::QstateData>,
                event: crate::unbound::ModuleEvent,
                entry: &mut crate::unbound::OutboundEntryMut,
            ) -> Option<ModuleExtState> {
                #[allow(unused_mut)]
                let mut ret = self.0.operate(qstate, event, entry);
                $(if let Some(state) = self.$i.operate(qstate, event, entry) {
                    if !matches!(ret, Some(ret) if ret.importance() >= state.importance()) {
                        ret = Some(state);
                    }
                })*
                ret
            }
            fn get_mem(&self, env: &mut crate::unbound::ModuleEnv<Self::EnvData>) -> usize {
                self.0.get_mem(env) $(* self.$i.get_mem(env))*
            }
            fn inform_super(
                &self,
                qstate: &mut crate::unbound::ModuleQstate<Self::QstateData>,
                super_qstate: &mut crate::unbound::ModuleQstate<std::ffi::c_void>,
            ) {
                self.0.inform_super(qstate, super_qstate);
                $(self.$i.inform_super(qstate, super_qstate);)*
            }
        }
    };
}

impl_tuple!();
impl_tuple!(1 B);
impl_tuple!(1 B, 2 C);
impl_tuple!(1 B, 2 C, 3 D);
impl_tuple!(1 B, 2 C, 3 D, 4 E);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q, 17 R);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q, 17 R, 18 S);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q, 17 R, 18 S, 19 T);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q, 17 R, 18 S, 19 T, 20 U);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q, 17 R, 18 S, 19 T, 20 U, 21 V);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q, 17 R, 18 S, 19 T, 20 U, 21 V, 22 W);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q, 17 R, 18 S, 19 T, 20 U, 21 V, 22 W, 23 X);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q, 17 R, 18 S, 19 T, 20 U, 21 V, 22 W, 23 X, 24 Y);
impl_tuple!(1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N, 14 O, 15 P, 16 Q, 17 R, 18 S, 19 T, 20 U, 21 V, 22 W, 23 X, 24 Y, 25 Z);
