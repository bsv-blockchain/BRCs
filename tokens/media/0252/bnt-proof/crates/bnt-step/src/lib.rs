//! BRC-255 proof steps. A step reads one transaction, every parent it spends
//! and the claims proven for those parents, and returns the claim for the
//! transaction: which assets its outputs carry validly. A zkVM proves a batch
//! of steps and verifies the parents' proofs inside it, so one constant-size
//! proof stands for the whole history back to each deploy.

pub mod batch;
pub mod journal;
pub mod payload;
pub mod script;
pub mod step;
pub mod tx;

pub use batch::batch;
pub use journal::{public_values, read_public_values, AssetRules, Claim, ProvenAsset};
pub use step::{step, Parent, StepError};
