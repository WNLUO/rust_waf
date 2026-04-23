use log::warn;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub(crate) fn read_lock<'a, T>(lock: &'a RwLock<T>, label: &'static str) -> RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("{label} lock poisoned; recovering with current value");
            poisoned.into_inner()
        }
    }
}

pub(crate) fn write_lock<'a, T>(
    lock: &'a RwLock<T>,
    label: &'static str,
) -> RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("{label} lock poisoned; recovering with current value");
            poisoned.into_inner()
        }
    }
}

pub(crate) fn mutex_lock<'a, T>(lock: &'a Mutex<T>, label: &'static str) -> MutexGuard<'a, T> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!("{label} mutex poisoned; recovering with current value");
            poisoned.into_inner()
        }
    }
}
