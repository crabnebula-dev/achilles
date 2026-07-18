//! Parallelism prelude for the corpus loop.
//!
//! On native we re-export rayon's prelude, so the scanner fans work across a
//! thread pool. On `wasm32` there is no thread pool (that would need
//! cross-origin isolation + `wasm-bindgen-rayon`), so we provide sequential
//! stand-ins with the same method names — `par_iter`, `flat_map_iter` — letting
//! the call sites in `lib.rs` / `scanner.rs` stay byte-for-byte identical.

#[cfg(not(target_arch = "wasm32"))]
pub use rayon::prelude::*;

#[cfg(target_arch = "wasm32")]
pub use sequential::*;

#[cfg(target_arch = "wasm32")]
mod sequential {
    /// `slice.par_iter()` / `vec.par_iter()` → a plain sequential iterator.
    pub trait ParCompat {
        type Item;
        fn par_iter(&self) -> core::slice::Iter<'_, Self::Item>;
    }

    impl<T> ParCompat for [T] {
        type Item = T;
        fn par_iter(&self) -> core::slice::Iter<'_, T> {
            self.iter()
        }
    }

    /// rayon's `flat_map_iter` has no std equivalent name; alias it to
    /// `flat_map` so `corpus.par_iter().flat_map_iter(..)` compiles unchanged.
    pub trait FlatMapIter: Iterator + Sized {
        fn flat_map_iter<U, F>(self, f: F) -> core::iter::FlatMap<Self, U, F>
        where
            F: FnMut(Self::Item) -> U,
            U: IntoIterator,
        {
            self.flat_map(f)
        }
    }

    impl<I: Iterator> FlatMapIter for I {}
}
