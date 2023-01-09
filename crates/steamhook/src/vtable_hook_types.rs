use std::any::Any;
use std::arch::asm;
use std::marker::{Tuple, PhantomData};
use std::sync::atomic::{AtomicPtr, Ordering::*};
use seq_macro::seq;

pub(crate) struct VtableHook {
    pub(crate) vtable: *mut *const (),
    pub(crate) i_fun: isize,
    pub(crate) asm_thunk: *const (),
    pub(crate) original: *const (),
    pub(crate) callback: Box<dyn Any>,

    pub(crate) next: AtomicPtr<VtableHook>,
    pub(crate) prev: AtomicPtr<VtableHook>
}

impl VtableHook {
    pub(crate) fn new<A: VtableHookArgs, F: Fn<A, Output: 'static> + 'static>(vtable: *mut *const (), i_fun: isize, cb: F) -> Self {
        Self { 
            vtable, 
            i_fun, 
            asm_thunk: std::ptr::null(),
            original: std::ptr::null(), 
            callback: Box::new(Box::new(cb) as Box::<dyn Fn<A, Output = F::Output>>),
            next: AtomicPtr::default(), 
            prev: AtomicPtr::default()
        }
    }
}
#[repr(C)]
pub struct VtableHookCtx<R: 'static> {
    thisptr: *mut (),
    data: *const VtableHook,
    phantom: PhantomData<*const R>
}
impl<R: 'static> Clone for VtableHookCtx<R> {
    fn clone(&self) -> Self {
        Self { thisptr: self.thisptr, data: self.data, phantom: self.phantom }   
    }
}
impl<R: 'static> Copy for VtableHookCtx<R> {}

impl<R: 'static> VtableHookCtx<R> {
    fn new(thisptr: *mut (), data: *const VtableHook) -> Self {
        Self { thisptr, data, phantom: PhantomData }
    }

    /// Get the pointer to the class instance this virtual function was called on.
    pub fn thisptr(&self) -> *mut () {
        self.thisptr
    }

    /// Call the original method, bypassing any other hooks set on it.
    pub unsafe fn call_orig<A: ThiscallArgs>(&self, args: A) -> R {
        args.thiscall(self.thisptr, (*self.data).original)
    }

    /// Call the next hook to be run after the current one, or the original function if none are left.
    pub unsafe fn call_next<A: ThiscallArgs>(&self, args: A) -> R {
        let data = &*self.data;
        let next = data.next.load(Relaxed);
        
        if next.is_null() {
            return self.call_orig::<A>(args);
        }
        let cb: &Box<dyn Fn<A::HookArgs<R>, Output = R>> = (*next).callback.downcast_ref_unchecked();
        cb.call(args.to_vtable_args(VtableHookCtx::new(self.thisptr, next)))
    }
}

pub trait VtableHookArgs: Tuple + 'static {
    type Ret: 'static;
    type Args: ThiscallArgs;

    fn thiscall_thunk() -> *const ();
    fn context(&self) -> VtableHookCtx<Self::Ret>;
    unsafe fn to_thiscall_args(self) -> Self::Args;
}

pub trait ThiscallArgs: Tuple + 'static {
    type HookArgs<R: 'static>: VtableHookArgs;

    fn to_vtable_args<R: 'static>(self, ctx: VtableHookCtx<R>) -> Self::HookArgs<R>;
    unsafe fn thiscall<R>(self, thisptr: *mut(), fun: *const ()) -> R;
}

pub trait VtableHookCb<A: VtableHookArgs>: Fn<A, Output: 'static> + 'static {
    fn thiscall_thunk() -> *const ();
    fn thiscall_thunk_ref(&self) -> *const ();
} 
impl<A: VtableHookArgs, F: Fn<A, Output = A::Ret> + 'static> VtableHookCb<A> for F {
    fn thiscall_thunk() -> *const () {
        A::thiscall_thunk()
    }
    fn thiscall_thunk_ref(&self) -> *const () {
        Self::thiscall_thunk()
    }
}


#[naked]
pub(crate) unsafe extern "C" fn dummy_call() -> *const () {
    asm!("", options(noreturn))
}

seq!(M in 0..=16 {
    #(
        seq!(N in 0..M {
            impl<#(T~N: 'static, )*> ThiscallArgs for (#(T~N, )*) {
                type HookArgs<R: 'static> = (VtableHookCtx<R>, #(T~N, )*);

                unsafe fn thiscall<R>(self, thisptr: *mut (), fun: *const ()) -> R {
                    #[cfg(target_arch = "x86")]
                    let f: unsafe extern "thiscall" fn(*mut(), #(a~N: T~N, )*) -> R = std::mem::transmute(fun);
                    #[cfg(target_arch = "x86_64")]
                    let f: unsafe extern "fastcall" fn(*mut(), #(a~N: T~N, )*) -> R = std::mem::transmute(fun);
                    f(thisptr, #(self.N, )*)
                }

                fn to_vtable_args<R: 'static>(self, ctx: VtableHookCtx<R>) -> Self::HookArgs<R> {
                    (ctx, #(self.N, )*)
                }
            }
        });

        seq!(N in 1..=M {
            impl<#(T~N: 'static, )* R: 'static> VtableHookArgs for (VtableHookCtx<R>, #(T~N, )*) {
                type Ret = R;
                type Args = (#(T~N, )*);

                fn context(&self) -> VtableHookCtx<R> {
                    self.0
                }

                fn thiscall_thunk() -> *const () {
                    #[cfg(target_arch = "x86")]
                    unsafe extern "thiscall" fn thunk<R: 'static, #(T~N: 'static, )*>(thisptr: *mut(), #(a~N: T~N, )*) -> R {
                        let hook_data = dummy_call() as *const VtableHook;
                        let cb: &Box<dyn Fn(VtableHookCtx<R>, #(T~N, )*) -> R> = (*hook_data).callback.downcast_ref_unchecked();
                        std::ops::Fn::call(&*cb, (VtableHookCtx::new(thisptr, hook_data), #(a~N, )*))
                    }
                    #[cfg(target_arch = "x86_64")]
                    unsafe extern "fastcall" fn thunk<R: 'static, #(T~N: 'static, )*>(thisptr: *mut(), #(a~N: T~N, )*) -> R {
                        let hook_data = dummy_call() as *const VtableHook;
                        let cb: &Box<dyn Fn(VtableHookCtx<R>, #(T~N, )*) -> R> = (*hook_data).callback.downcast_ref_unchecked();
                        std::ops::Fn::call(&*cb, (VtableHookCtx::new(thisptr, hook_data), #(a~N, )*))
                    }
                    thunk::<R, #(T~N, )*> as *const ()
                }

                unsafe fn to_thiscall_args(self) -> Self::Args {
                    (#(self.N,)*)
                }
            }
        });
    )*
});

pub struct OptionHook<R: 'static, A: VtableHookArgs<Ret = R> + Clone, F: Fn<A, Output = Option<R>>> {
    closure: F,
    phantom: PhantomData<*const A>
}
impl<R: 'static, A: VtableHookArgs<Ret = R> + Clone, F: Fn<A, Output = Option<R>>> OptionHook<R, A, F> {
    fn do_call(&self, args: A) -> R {
        match self.closure.call(args.clone()) {
            Some(ret) => ret,
            None => unsafe { args.context().call_next(args.to_thiscall_args()) }
        }
    }
}
impl<A: VtableHookArgs<Ret = R> + Clone, R: 'static, F: Fn<A, Output = Option<R>>> FnOnce<A> for OptionHook<R, A, F> {
    type Output = R;
    extern "rust-call" fn call_once(self, args: A) -> Self::Output {
        self.do_call(args)
    }
}
impl<A: VtableHookArgs<Ret = R> + Clone, R: 'static, F: Fn<A, Output = Option<R>>> FnMut<A> for OptionHook<R, A, F> {
    extern "rust-call" fn call_mut(&mut self, args: A) -> Self::Output {
        self.do_call(args)
    }
}
impl<A: VtableHookArgs<Ret = R> + Clone, R: 'static, F: Fn<A, Output = Option<R>>> Fn<A> for OptionHook<R, A, F> {
    extern "rust-call" fn call(&self, args: A) -> Self::Output {
        self.do_call(args)
    }
}
pub trait OptionHookable<A: VtableHookArgs<Ret = R> + Clone, R: 'static>: Sized + Fn<A, Output = Option<R>> {
    fn unwrap_or_next(self) -> OptionHook<R, A, Self>;
}
impl<A: VtableHookArgs<Ret = R> + Clone, R: 'static, F: Fn<A, Output = Option<R>>> OptionHookable<A, R> for F {
    fn unwrap_or_next(self) -> OptionHook<R, A, Self> {
        OptionHook { closure: self, phantom: PhantomData }
    }
}

pub struct FilterHook<A: VtableHookArgs<Ret = F::Output> + Clone, F: Fn<A, Output: 'static>, G: Fn(A) -> bool> {
    closure: F,
    filter: G,
    phantom: PhantomData<*const A>
}
impl<A: VtableHookArgs<Ret = F::Output> + Clone, F: Fn<A>, G: Fn(A) -> bool> FilterHook<A, F, G> {
    fn do_call(&self, args: A) -> F::Output {
        match (self.filter)(args.clone()) {
            true => self.closure.call(args),
            false => unsafe { args.context().call_next(args.to_thiscall_args()) }
        }
    }
}
impl<A: VtableHookArgs<Ret = F::Output> + Clone, F: Fn<A>, G: Fn(A) -> bool> FnOnce<A> for FilterHook<A, F, G> {
    type Output = F::Output;
    extern "rust-call" fn call_once(self, args: A) -> Self::Output {
        self.do_call(args)
    }
}
impl<A: VtableHookArgs<Ret = F::Output> + Clone, F: Fn<A>, G: Fn(A) -> bool> FnMut<A> for FilterHook<A, F, G> {
    extern "rust-call" fn call_mut(&mut self, args: A) -> Self::Output {
        self.do_call(args)
    }
}
impl<A: VtableHookArgs<Ret = F::Output> + Clone, F: Fn<A>, G: Fn(A) -> bool> Fn<A> for FilterHook<A, F, G> {
    extern "rust-call" fn call(&self, args: A) -> Self::Output {
        self.do_call(args)
    }
}
pub trait FilterHookable<A: VtableHookArgs<Ret = Self::Output> + Clone>: Fn<A> + Sized {
    fn with_filter<P: Fn(A) -> bool>(self, predicate: P) -> FilterHook<A, Self, P>;
}
impl<A: VtableHookArgs<Ret = F::Output> + Clone, F: Fn<A>> FilterHookable<A> for F {
    fn with_filter<P: Fn(A) -> bool>(self, predicate: P) -> FilterHook<A, Self, P> {
        FilterHook { closure: self, filter: predicate, phantom: PhantomData }
    }
}