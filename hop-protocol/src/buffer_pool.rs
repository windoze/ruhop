//! Memory pool for reducing allocations in packet processing
//!
//! This module provides a simple buffer pool that allows reusing allocated
//! buffers for packet encoding, encryption, and decryption operations.
//!
//! # Usage
//!
//! ```rust
//! use hop_protocol::BufferPool;
//!
//! // Create a pool with default settings
//! let pool = BufferPool::new();
//!
//! // Get a buffer from the pool
//! let mut buf = pool.get();
//! buf.extend_from_slice(b"hello");
//!
//! // When PooledBuffer is dropped, it returns to the pool automatically
//! drop(buf);
//!
//! // Get another buffer - this may reuse the previous one
//! let buf2 = pool.get();
//! ```

use std::cell::RefCell;
use std::ops::{Deref, DerefMut};

/// Default buffer capacity (2KB - typical MTU + overhead)
const DEFAULT_BUFFER_CAPACITY: usize = 2048;

/// Maximum number of buffers to keep in the pool per thread
const DEFAULT_MAX_POOL_SIZE: usize = 16;

/// Maximum buffer size to return to pool (larger buffers are just dropped)
const MAX_POOLABLE_SIZE: usize = 65536;

thread_local! {
    static THREAD_POOL: RefCell<LocalPool> = RefCell::new(LocalPool::new(
        DEFAULT_MAX_POOL_SIZE,
        DEFAULT_BUFFER_CAPACITY,
    ));
}

/// Thread-local buffer pool for zero-allocation buffer reuse
struct LocalPool {
    buffers: Vec<Vec<u8>>,
    max_size: usize,
    default_capacity: usize,
}

impl LocalPool {
    fn new(max_size: usize, default_capacity: usize) -> Self {
        Self {
            buffers: Vec::with_capacity(max_size),
            max_size,
            default_capacity,
        }
    }

    fn get(&mut self) -> Vec<u8> {
        self.buffers
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.default_capacity))
    }

    fn get_with_capacity(&mut self, capacity: usize) -> Vec<u8> {
        // Try to find a buffer with sufficient capacity
        if let Some(pos) = self.buffers.iter().position(|b| b.capacity() >= capacity) {
            self.buffers.swap_remove(pos)
        } else {
            Vec::with_capacity(capacity.max(self.default_capacity))
        }
    }

    fn put(&mut self, mut buf: Vec<u8>) {
        // Only pool buffers that aren't too large
        if buf.capacity() <= MAX_POOLABLE_SIZE && self.buffers.len() < self.max_size {
            buf.clear();
            self.buffers.push(buf);
        }
        // Otherwise, let it drop and deallocate
    }
}

/// A buffer pool for reusing allocated memory
///
/// This is a zero-sized type that provides access to thread-local buffer pools.
/// Creating multiple `BufferPool` instances is cheap and they all share the
/// same underlying thread-local storage.
#[derive(Debug, Clone, Copy, Default)]
pub struct BufferPool;

impl BufferPool {
    /// Create a new buffer pool handle
    ///
    /// This is a zero-cost operation as it just provides access to the
    /// thread-local pool.
    #[inline]
    pub fn new() -> Self {
        Self
    }

    /// Get a buffer from the pool
    ///
    /// The buffer will have its length set to 0 but may have pre-allocated
    /// capacity from previous use.
    #[inline]
    pub fn get(&self) -> PooledBuffer {
        let buf = THREAD_POOL.with(|pool| pool.borrow_mut().get());
        PooledBuffer { inner: Some(buf) }
    }

    /// Get a buffer with at least the specified capacity
    ///
    /// Tries to find an existing buffer with sufficient capacity before
    /// allocating a new one.
    #[inline]
    pub fn get_with_capacity(&self, capacity: usize) -> PooledBuffer {
        let buf = THREAD_POOL.with(|pool| pool.borrow_mut().get_with_capacity(capacity));
        PooledBuffer { inner: Some(buf) }
    }

    /// Pre-warm the pool by allocating buffers
    ///
    /// This can be useful to avoid allocation jitter during initial packet processing.
    pub fn prewarm(&self, count: usize) {
        THREAD_POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            let to_add = count.min(pool.max_size.saturating_sub(pool.buffers.len()));
            let capacity = pool.default_capacity;
            for _ in 0..to_add {
                pool.buffers.push(Vec::with_capacity(capacity));
            }
        });
    }

    /// Clear all pooled buffers, releasing memory
    pub fn clear(&self) {
        THREAD_POOL.with(|pool| {
            pool.borrow_mut().buffers.clear();
        });
    }

    /// Get the current number of buffers in the pool
    pub fn len(&self) -> usize {
        THREAD_POOL.with(|pool| pool.borrow().buffers.len())
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A buffer obtained from a pool that returns itself when dropped
///
/// This type implements `Deref` and `DerefMut` to `Vec<u8>`, so it can be
/// used anywhere a `Vec<u8>` reference is expected.
pub struct PooledBuffer {
    inner: Option<Vec<u8>>,
}

impl PooledBuffer {
    /// Create a new pooled buffer wrapping an existing Vec
    ///
    /// When dropped, this buffer will be returned to the thread-local pool.
    #[inline]
    pub fn from_vec(vec: Vec<u8>) -> Self {
        Self { inner: Some(vec) }
    }

    /// Consume this pooled buffer and return the inner Vec
    ///
    /// The returned Vec will NOT be returned to the pool when dropped.
    /// Use this when you need to pass ownership to code that expects `Vec<u8>`.
    #[inline]
    pub fn into_vec(mut self) -> Vec<u8> {
        self.inner.take().unwrap()
    }

    /// Get the capacity of the underlying buffer
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.as_ref().map(|v| v.capacity()).unwrap_or(0)
    }
}

impl Default for PooledBuffer {
    fn default() -> Self {
        BufferPool::new().get()
    }
}

impl Deref for PooledBuffer {
    type Target = Vec<u8>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}

impl DerefMut for PooledBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.inner.take() {
            THREAD_POOL.with(|pool| {
                pool.borrow_mut().put(buf);
            });
        }
    }
}

impl AsRef<[u8]> for PooledBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref().unwrap()
    }
}

impl AsMut<[u8]> for PooledBuffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut().unwrap()
    }
}

impl std::io::Write for PooledBuffer {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.as_mut().unwrap().write(buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl From<Vec<u8>> for PooledBuffer {
    #[inline]
    fn from(vec: Vec<u8>) -> Self {
        Self::from_vec(vec)
    }
}

impl From<PooledBuffer> for Vec<u8> {
    #[inline]
    fn from(buf: PooledBuffer) -> Self {
        buf.into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_basic() {
        let pool = BufferPool::new();

        // Get a buffer and use it
        let mut buf = pool.get();
        buf.extend_from_slice(b"hello world");
        assert_eq!(&buf[..], b"hello world");

        // Drop should return to pool
        drop(buf);
        assert_eq!(pool.len(), 1);

        // Get another buffer - should reuse
        let buf2 = pool.get();
        assert_eq!(pool.len(), 0);
        assert!(buf2.is_empty()); // Should be cleared
        assert!(buf2.capacity() >= DEFAULT_BUFFER_CAPACITY);

        drop(buf2);
    }

    #[test]
    fn test_buffer_pool_capacity() {
        let pool = BufferPool::new();

        // Request specific capacity
        let buf = pool.get_with_capacity(4096);
        assert!(buf.capacity() >= 4096);

        drop(buf);

        // Should get a buffer with at least that capacity
        let buf2 = pool.get_with_capacity(4096);
        assert!(buf2.capacity() >= 4096);

        drop(buf2);
    }

    #[test]
    fn test_pooled_buffer_into_vec() {
        let pool = BufferPool::new();

        let mut buf = pool.get();
        buf.extend_from_slice(b"data");

        let vec = buf.into_vec();
        assert_eq!(&vec[..], b"data");

        // Pool should be empty since we took ownership
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_buffer_pool_prewarm() {
        let pool = BufferPool::new();
        pool.clear();

        pool.prewarm(4);
        assert_eq!(pool.len(), 4);

        // Getting buffers should use prewarmed ones
        let _b1 = pool.get();
        let _b2 = pool.get();
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_pooled_buffer_from_vec() {
        let pool = BufferPool::new();
        pool.clear();

        let vec = vec![1, 2, 3, 4];
        let buf = PooledBuffer::from_vec(vec);
        assert_eq!(&buf[..], &[1, 2, 3, 4]);

        // When dropped, should go to pool
        drop(buf);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_pool_max_size() {
        let pool = BufferPool::new();
        pool.clear();

        // Create more buffers than max pool size
        let buffers: Vec<_> = (0..DEFAULT_MAX_POOL_SIZE + 5).map(|_| pool.get()).collect();

        // Drop all buffers
        drop(buffers);

        // Pool should only keep up to max_size
        assert!(pool.len() <= DEFAULT_MAX_POOL_SIZE);
    }

    #[test]
    fn test_large_buffer_not_pooled() {
        let pool = BufferPool::new();
        pool.clear();

        // Create a very large buffer
        let mut buf = pool.get();
        buf.reserve(MAX_POOLABLE_SIZE + 1);
        buf.extend(std::iter::repeat_n(0u8, MAX_POOLABLE_SIZE + 1));

        let initial_len = pool.len();
        drop(buf);

        // Large buffer should not be pooled
        assert_eq!(pool.len(), initial_len);
    }

    #[test]
    fn test_pooled_buffer_write_trait() {
        use std::io::Write;

        let pool = BufferPool::new();
        let mut buf = pool.get();

        write!(buf, "hello {}", 42).unwrap();
        assert_eq!(&buf[..], b"hello 42");
    }

    // ========================================================================
    // Multi-threaded tests
    // ========================================================================

    #[test]
    fn test_thread_local_isolation() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let barrier = Arc::new(Barrier::new(3));
        let mut handles = vec![];

        // Spawn multiple threads that each use the pool
        for thread_id in 0..3 {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                let pool = BufferPool::new();
                pool.clear();

                // Each thread prewarms its own pool
                pool.prewarm(5);
                assert_eq!(pool.len(), 5);

                // Wait for all threads to prewarm
                barrier.wait();

                // Each thread should have its own pool with 5 buffers
                assert_eq!(pool.len(), 5);

                // Get buffers and verify they work
                let mut buf = pool.get();
                buf.extend_from_slice(&[thread_id as u8; 100]);
                assert_eq!(buf[0], thread_id as u8);

                // Return buffer
                drop(buf);

                // Pool should still have 5 buffers (4 prewarmed + 1 returned)
                // Actually it should be 5 since we took 1 out and put 1 back
                assert_eq!(pool.len(), 5);

                thread_id
            });
            handles.push(handle);
        }

        // Collect results
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_concurrent_buffer_usage() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let num_threads = 4;
        let iterations = 100;
        let barrier = Arc::new(Barrier::new(num_threads));
        let mut handles = vec![];

        for _ in 0..num_threads {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                let pool = BufferPool::new();
                pool.clear();

                // Wait for all threads to start
                barrier.wait();

                // Each thread repeatedly gets and returns buffers
                for i in 0..iterations {
                    let mut buf = pool.get();
                    buf.extend_from_slice(&[i as u8; 50]);
                    assert_eq!(buf.len(), 50);
                    // Buffer returned to pool on drop
                }

                // Pool should have accumulated some buffers
                pool.len()
            });
            handles.push(handle);
        }

        // All threads should complete successfully
        let pool_sizes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Each thread's pool should have some buffers (up to max size)
        for size in pool_sizes {
            assert!(size > 0);
            assert!(size <= DEFAULT_MAX_POOL_SIZE);
        }
    }

    #[test]
    fn test_buffer_data_isolation_across_threads() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let num_threads = 4;
        let barrier = Arc::new(Barrier::new(num_threads));
        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                let pool = BufferPool::new();

                // Get a buffer and fill it with thread-specific data
                let mut buf = pool.get();
                buf.extend(std::iter::repeat_n(thread_id as u8, 1000));

                // Wait for all threads to fill their buffers
                barrier.wait();

                // Verify our data hasn't been corrupted by other threads
                assert!(buf.iter().all(|&b| b == thread_id as u8));

                // Drop and get again
                drop(buf);
                let buf2 = pool.get();

                // New buffer should be empty (cleared on return to pool)
                assert!(buf2.is_empty());

                thread_id
            });
            handles.push(handle);
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.len(), num_threads);
    }

    #[test]
    fn test_into_vec_cross_thread() {
        use std::sync::mpsc;
        use std::thread;

        let (tx, rx) = mpsc::channel();

        // Thread 1: Create buffer, convert to Vec, send to thread 2
        let handle1 = thread::spawn(move || {
            let pool = BufferPool::new();
            let mut buf = pool.get();
            buf.extend_from_slice(b"hello from thread 1");

            // Convert to Vec to transfer ownership
            let vec = buf.into_vec();
            tx.send(vec).unwrap();
        });

        // Thread 2: Receive Vec, verify contents
        let handle2 = thread::spawn(move || {
            let vec = rx.recv().unwrap();
            assert_eq!(&vec[..], b"hello from thread 1");

            // Can convert back to PooledBuffer in this thread
            let buf = PooledBuffer::from_vec(vec);
            assert_eq!(&buf[..], b"hello from thread 1");
        });

        handle1.join().unwrap();
        handle2.join().unwrap();
    }

    #[test]
    fn test_high_contention() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let num_threads = 8;
        let iterations = 1000;
        let barrier = Arc::new(Barrier::new(num_threads));
        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                let pool = BufferPool::new();

                // Wait for all threads
                barrier.wait();

                let mut success_count = 0;
                for i in 0..iterations {
                    // Get buffer
                    let mut buf = pool.get_with_capacity(128);
                    buf.extend_from_slice(&[thread_id as u8; 64]);
                    buf.extend_from_slice(&[(i % 256) as u8; 64]);

                    // Verify
                    if buf.len() == 128
                        && buf[..64].iter().all(|&b| b == thread_id as u8)
                        && buf[64..].iter().all(|&b| b == (i % 256) as u8)
                    {
                        success_count += 1;
                    }
                }

                success_count
            });
            handles.push(handle);
        }

        // All operations should succeed
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for count in results {
            assert_eq!(count, iterations);
        }
    }
}
