use std::marker::{PhantomData, Tuple};

/// Closure wrapper turning a FnOnce which takes a tuple as a sole 
/// argument into one which takes tuple elements as arguments.
pub struct SUnpackedFnOnce<A: Tuple, F: FnOnce<(A, )>> {
    closure: F,
    phantom: PhantomData<*const A>
}
impl<A: Tuple, F: FnOnce<(A,)>> FnOnce<A> for SUnpackedFnOnce<A, F> {
    type Output = F::Output;
    extern "rust-call" fn call_once(self, args: A) -> Self::Output {
        (self.closure)(args)
    }
}

/// Closure wrapper turning a FnMut which takes a tuple as a sole 
/// argument into one which takes tuple elements as arguments.
pub struct SUnpackedFnMut<A: Tuple, F: FnMut<(A,)>> {
    closure: F,
    phantom: PhantomData<*const A>
}
impl<A: Tuple, F: FnMut<(A,)>> FnOnce<A> for SUnpackedFnMut<A, F> {
    type Output = F::Output;
    extern "rust-call" fn call_once(self, args: A) -> Self::Output {
        let mut cl = self.closure;
        cl(args)
    }
}
impl<A: Tuple, F: FnMut<(A,)>> FnMut<A> for SUnpackedFnMut<A, F> {
    extern "rust-call" fn call_mut(&mut self, args: A) -> Self::Output {
        (self.closure)(args)
    }
}

/// Closure wrapper turning a Fn which takes a tuple as a sole 
/// argument into one which takes tuple elements as arguments.
pub struct SUnpackedFn<A: Tuple, F: Fn<(A,)>> {
    closure: F,
    phantom: PhantomData<*const A>
}
impl<A: Tuple, F: Fn<(A,)>> FnOnce<A> for SUnpackedFn<A, F> {
    type Output = F::Output;
    extern "rust-call" fn call_once(self, args: A) -> Self::Output {
        (self.closure)(args)
    }
}
impl<A: Tuple, F: Fn<(A,)>> FnMut<A> for SUnpackedFn<A, F> {
    extern "rust-call" fn call_mut(&mut self, args: A) -> Self::Output {
        (self.closure)(args)
    }
}
impl<A: Tuple, F: Fn<(A,)>> Fn<A> for SUnpackedFn<A, F> {
    extern "rust-call" fn call(&self, args: A) -> Self::Output {
        (self.closure)(args)
    }
}

pub trait UnpackedFnOnce<A: Tuple> : FnOnce<(A,)> + Sized {
    fn unpack_once(self) -> SUnpackedFnOnce<A, Self>;
}
impl<A: Tuple, F: FnOnce<(A,)>> UnpackedFnOnce<A> for F {
    fn unpack_once(self) -> SUnpackedFnOnce<A, Self> {
        SUnpackedFnOnce { closure: self, phantom: PhantomData }
    }
}

pub trait UnpackedFnMut<A: Tuple> : FnMut<(A,)> + Sized {
    fn unpack_mut(self) -> SUnpackedFnMut<A, Self>;
}
impl<A: Tuple, F: FnMut<(A,)>> UnpackedFnMut<A> for F {
    fn unpack_mut(self) -> SUnpackedFnMut<A, Self> {
        SUnpackedFnMut { closure: self, phantom: PhantomData }
    }
}

pub trait UnpackedFn<A: Tuple> : Fn<(A,)> + Sized {
    fn unpack(self) -> SUnpackedFn<A, Self>;
}
impl<A: Tuple, F: Fn<(A,)>> UnpackedFn<A> for F {
    fn unpack(self) -> SUnpackedFn<A, Self> {
        SUnpackedFn { closure: self, phantom: PhantomData }
    }
}