use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

pub trait RwSingleton: Sync + Send + Sized + 'static {
    fn get_or_create() -> &'static RwLock<Self>;

    fn instance<'a>() -> RwLockReadGuard<'a, Self> {
        Self::get_or_create().read().expect("RwSingleton lock poisoned")
    }
    fn instance_mut<'a>() -> RwLockWriteGuard<'a, Self> {
        Self::get_or_create().write().expect("RwSingleton lock poisoned")
    }
}