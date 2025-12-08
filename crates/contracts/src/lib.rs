#![warn(clippy::all, clippy::pedantic)]

mod dual_currency_deposit;
mod options;
mod simple_storage;
mod storage_inc;

pub use dual_currency_deposit::*;
pub use options::*;
pub use simple_storage::*;
pub use storage_inc::*;