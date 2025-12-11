#![warn(clippy::all, clippy::pedantic)]

mod dual_currency_deposit;
mod options;
mod simple_storage;
mod cmr_storage;
mod unlimited_storage;

pub use dual_currency_deposit::*;
pub use options::*;
pub use simple_storage::*;
pub use cmr_storage::*;