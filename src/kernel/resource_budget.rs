//! Store-wide resource accounting for wasm sub-instances.
//!
//! Both wasm entry points — the `wasm` step type and the `script`
//! step type's interpreter sub-instance — hand wasmtime a
//! [`wasmtime::ResourceLimiter`]. This module holds the accounting
//! both of them share.
//!
//! ## Why this is not a per-object cap
//!
//! The obvious limiter answers `memory_growing` and `table_growing`
//! with `desired <= cap`, where `desired` is the size of the *one*
//! memory or table being grown. That reads like a budget and is not
//! one: wasmtime calls the limiter once per object, so a module
//! declaring N memories gets N × cap, and the count of objects is
//! itself governed by wasmtime's defaults —
//! `instances()`/`tables()`/`memories()` all default to **10,000**
//! unless the limiter overrides them.
//!
//! Under such a limiter a module declaring 100 memories of 1 MiB each
//! passes a 1 MiB cap without a trap and commits on the order of
//! 100 MiB of host memory — the cap is decorative. The `wasm` step
//! type is reachable this way, since its module comes straight from a
//! plugin manifest's `wasmModules`.
//!
//! ## What this does instead
//!
//! [`ResourceBudget`] tracks the **running total** across every memory
//! and every table in the store. Each call computes
//! `committed - current + desired` — subtracting this object's present
//! contribution before adding its requested one — and denies when the
//! new total would exceed the cap. Object counts are capped too, well
//! below wasmtime's defaults, so a module cannot approach the byte
//! budget by way of thousands of tiny objects.

use crate::kernel::RuntimeLimits;

/// Store-wide memory and table accounting shared by every wasm
/// sub-instance limiter. See the module docs.
#[derive(Debug)]
pub(crate) struct ResourceBudget {
    max_memory_bytes: usize,
    max_table_elements: usize,
    max_instances: usize,
    max_tables: usize,
    max_memories: usize,
    /// Sum of every memory's current size in this store.
    committed_memory_bytes: usize,
    /// Sum of every table's current element count in this store.
    committed_table_elements: usize,
}

impl ResourceBudget {
    pub(crate) fn new(limits: &RuntimeLimits) -> Self {
        Self {
            max_memory_bytes: limits.max_memory_bytes,
            max_table_elements: limits.max_table_elements,
            max_instances: limits.max_instances,
            max_tables: limits.max_tables,
            max_memories: limits.max_memories,
            committed_memory_bytes: 0,
            committed_table_elements: 0,
        }
    }

    /// `ResourceLimiter::memory_growing`, as a store-wide check.
    pub(crate) fn memory_growing(&mut self, current: usize, desired: usize) -> bool {
        let Some(new_total) = self
            .committed_memory_bytes
            .checked_sub(current)
            .and_then(|rest| rest.checked_add(desired))
        else {
            // `current` exceeding what we have committed means our
            // accounting drifted from wasmtime's. Deny rather than
            // guess: a wrong allow here is unbounded host allocation.
            return false;
        };
        if new_total > self.max_memory_bytes {
            return false;
        }
        self.committed_memory_bytes = new_total;
        true
    }

    /// `ResourceLimiter::table_growing`, as a store-wide check.
    pub(crate) fn table_growing(&mut self, current: usize, desired: usize) -> bool {
        let Some(new_total) = self
            .committed_table_elements
            .checked_sub(current)
            .and_then(|rest| rest.checked_add(desired))
        else {
            return false;
        };
        if new_total > self.max_table_elements {
            return false;
        }
        self.committed_table_elements = new_total;
        true
    }

    pub(crate) fn max_instances(&self) -> usize {
        self.max_instances
    }

    pub(crate) fn max_tables(&self) -> usize {
        self.max_tables
    }

    pub(crate) fn max_memories(&self) -> usize {
        self.max_memories
    }
}

/// Write the `ResourceLimiter` methods that just forward to a
/// [`ResourceBudget`] field.
///
/// Two store-data types implement `ResourceLimiter` with identical
/// bodies. A macro keeps them from drifting — a fix applied to one
/// would otherwise not reach the other.
macro_rules! impl_budget_limiter {
    ($ty:ty, $field:ident) => {
        impl wasmtime::ResourceLimiter for $ty {
            fn memory_growing(
                &mut self,
                current: usize,
                desired: usize,
                _maximum: Option<usize>,
            ) -> wasmtime::Result<bool> {
                Ok(self.$field.memory_growing(current, desired))
            }

            fn table_growing(
                &mut self,
                current: usize,
                desired: usize,
                _maximum: Option<usize>,
            ) -> wasmtime::Result<bool> {
                Ok(self.$field.table_growing(current, desired))
            }

            fn instances(&self) -> usize {
                self.$field.max_instances()
            }

            fn tables(&self) -> usize {
                self.$field.max_tables()
            }

            fn memories(&self) -> usize {
                self.$field.max_memories()
            }
        }
    };
}

pub(crate) use impl_budget_limiter;

#[cfg(test)]
mod tests {
    use super::ResourceBudget;
    use crate::kernel::RuntimeLimits;

    fn budget(bytes: usize, elements: usize) -> ResourceBudget {
        ResourceBudget::new(
            &RuntimeLimits::default()
                .with_max_memory_bytes(bytes)
                .with_max_table_elements(elements),
        )
    }

    /// The core property in one test: N memories each under the cap
    /// must not collectively exceed it. A per-object check would allow
    /// every one of these grows.
    #[test]
    fn many_memories_share_one_budget() {
        let mut b = budget(4096, 64);
        assert!(b.memory_growing(0, 4096), "first memory fits exactly");
        assert!(
            !b.memory_growing(0, 1),
            "a second memory has no budget left, even for one byte"
        );
    }

    #[test]
    fn many_tables_share_one_budget() {
        let mut b = budget(4096, 64);
        assert!(b.table_growing(0, 64));
        assert!(!b.table_growing(0, 1));
    }

    /// Growth of an existing object is charged only for the delta —
    /// otherwise a memory growing 1 page at a time would exhaust the
    /// budget in `cap / page` steps regardless of its actual size.
    #[test]
    fn growing_one_object_charges_only_the_delta() {
        let mut b = budget(300, 64);
        assert!(b.memory_growing(0, 100));
        assert!(b.memory_growing(100, 200));
        assert!(b.memory_growing(200, 300));
        assert!(!b.memory_growing(300, 301), "301 exceeds the 300 cap");
    }

    /// Two objects growing independently are both charged, and the
    /// second is denied at the point their *sum* crosses the cap.
    #[test]
    fn two_objects_are_denied_when_their_sum_crosses_the_cap() {
        let mut b = budget(300, 64);
        assert!(b.memory_growing(0, 200), "first takes 200 of 300");
        assert!(b.memory_growing(0, 100), "second takes the remaining 100");
        assert!(!b.memory_growing(100, 101), "nothing left for the second");
    }

    /// A denied grow must not consume budget — otherwise a module
    /// could exhaust the cap purely by asking for things it never got.
    #[test]
    fn a_denied_grow_leaves_the_budget_untouched() {
        let mut b = budget(300, 64);
        assert!(!b.memory_growing(0, 400));
        assert!(b.memory_growing(0, 300), "the full budget is still there");
    }
}
