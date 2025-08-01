// Re-export the main function and types for benchmarking
pub use crate::main::*;

// Export the main function module
mod main {
    // Include the main.rs content here
    include!("main.rs");
}

// Re-export types from dependencies that benchmarks need
pub use bin_utils::{AggFunc, Prio3Gadgets};
pub use bridge::id_tracker::IdGen;
pub use common::VERIFY_KEY_SIZE; 