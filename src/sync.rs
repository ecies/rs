use core::sync::atomic::{AtomicU32, Ordering};
use lock_api::{GuardSend, RawRwLock};

/// A raw reader-writer lock implementation for no_std environments
///
/// This uses a spinlock approach with atomic operations:
/// - State 0: unlocked
/// - State 1..WRITER: number of readers
/// - State WRITER: exclusive writer lock
const WRITER: u32 = u32::MAX;
const MAX_READERS: u32 = u32::MAX - 1;

pub struct RawSpinRwLock {
    state: AtomicU32,
}

unsafe impl RawRwLock for RawSpinRwLock {
    const INIT: Self = RawSpinRwLock {
        state: AtomicU32::new(0),
    };

    type GuardMarker = GuardSend;

    #[inline]
    fn lock_shared(&self) {
        while !self.try_lock_shared() {
            // Spin with a hint to the CPU
            core::hint::spin_loop();
        }
    }

    #[inline]
    fn try_lock_shared(&self) -> bool {
        let mut state = self.state.load(Ordering::Relaxed);

        loop {
            // Cannot acquire read lock if writer is present or too many readers
            if state >= MAX_READERS {
                return false;
            }

            // Try to increment reader count
            match self
                .state
                .compare_exchange_weak(state, state + 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(new_state) => state = new_state,
            }
        }
    }

    #[inline]
    unsafe fn unlock_shared(&self) {
        // Decrement reader count
        self.state.fetch_sub(1, Ordering::Release);
    }

    #[inline]
    fn lock_exclusive(&self) {
        while !self.try_lock_exclusive() {
            core::hint::spin_loop();
        }
    }

    #[inline]
    fn try_lock_exclusive(&self) -> bool {
        // Try to acquire exclusive lock (state must be 0)
        self.state
            .compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    #[inline]
    unsafe fn unlock_exclusive(&self) {
        self.state.store(0, Ordering::Release);
    }
}

/// A reader-writer lock for no_std environments
///
/// This allows multiple concurrent readers or a single writer.
pub(crate) type RwLock<T> = lock_api::RwLock<RawSpinRwLock, T>;

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Arc;
    use std::thread;
    use std::vec::Vec;

    #[test]
    fn test_multiple_readers() {
        let lock = RwLock::new(42);

        let r1 = lock.read();
        let r2 = lock.read();
        let r3 = lock.read();

        assert_eq!(*r1, 42);
        assert_eq!(*r2, 42);
        assert_eq!(*r3, 42);
    }

    #[test]
    fn test_exclusive_writer() {
        let lock = RwLock::new(42);

        let mut writer = lock.write();
        *writer = 100;
        drop(writer);

        let reader = lock.read();
        assert_eq!(*reader, 100);
    }

    #[test]
    fn test_try_write_fails_with_readers() {
        let lock = RwLock::new(42);

        let _reader = lock.read();
        assert!(lock.try_write().is_none());
    }

    #[test]
    fn test_try_read_fails_with_writer() {
        let lock = RwLock::new(42);

        let _writer = lock.write();
        assert!(lock.try_read().is_none());
    }

    #[test]
    fn test_concurrent_readers() {
        let lock = Arc::new(RwLock::new(0));
        let mut handles = Vec::new();

        // Spawn 10 reader threads
        for _ in 0..10 {
            let lock = Arc::clone(&lock);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let value = lock.read();
                    // Just read the value
                    let _ = *value;
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_writers() {
        let lock = Arc::new(RwLock::new(0));
        let mut handles = Vec::new();

        // Spawn 10 writer threads, each incrementing 100 times
        for _ in 0..10 {
            let lock = Arc::clone(&lock);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let mut value = lock.write();
                    *value += 1;
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should be exactly 1000
        assert_eq!(*lock.read(), 1000);
    }

    #[test]
    fn test_mixed_readers_writers() {
        let lock = Arc::new(RwLock::new(0));
        let mut handles = Vec::new();

        // Spawn 5 writer threads
        for _ in 0..5 {
            let lock = Arc::clone(&lock);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let mut value = lock.write();
                    *value += 1;
                }
            });
            handles.push(handle);
        }

        // Spawn 10 reader threads
        for _ in 0..10 {
            let lock = Arc::clone(&lock);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let value = lock.read();
                    // Verify value is valid (between 0 and 500)
                    assert!(*value <= 500);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(*lock.read(), 500);
    }

    #[test]
    fn test_writer_blocks_readers() {
        let lock = Arc::new(RwLock::new(0));
        let lock2 = Arc::clone(&lock);

        let writer = lock.write();

        // Spawn a reader thread - it should block
        let handle = thread::spawn(move || {
            let value = lock2.read();
            *value
        });

        // Sleep a bit to ensure reader is blocked
        thread::sleep(std::time::Duration::from_millis(50));

        // Release writer lock
        drop(writer);

        // Now reader should complete
        let result = handle.join().unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn test_readers_block_writer() {
        let lock = Arc::new(RwLock::new(0));
        let lock2 = Arc::clone(&lock);

        let reader = lock.read();

        // Spawn a writer thread - it should block
        let handle = thread::spawn(move || {
            let mut value = lock2.write();
            *value = 42;
        });

        // Sleep a bit to ensure writer is blocked
        thread::sleep(std::time::Duration::from_millis(50));

        // Release reader lock
        drop(reader);

        // Wait for writer to complete
        handle.join().unwrap();

        assert_eq!(*lock.read(), 42);
    }

    #[test]
    fn test_stress_test() {
        let lock = Arc::new(RwLock::new(Vec::new()));
        let mut handles = Vec::new();

        // Spawn multiple writers that push to the vec
        for i in 0..5 {
            let lock = Arc::clone(&lock);
            let handle = thread::spawn(move || {
                for j in 0..20 {
                    let mut vec = lock.write();
                    vec.push(i * 100 + j);
                }
            });
            handles.push(handle);
        }

        // Spawn multiple readers that check vec length
        for _ in 0..5 {
            let lock = Arc::clone(&lock);
            let handle = thread::spawn(move || {
                for _ in 0..50 {
                    let vec = lock.read();
                    let len = vec.len();
                    // Length should be between 0 and 100
                    assert!(len <= 100);
                    thread::yield_now();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Final check - should have exactly 100 elements
        assert_eq!(lock.read().len(), 100);
    }
}
