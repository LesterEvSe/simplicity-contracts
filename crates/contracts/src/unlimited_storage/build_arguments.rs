use std::collections::HashMap;

use simplicityhl::{Arguments, str::WitnessName, value::UIntValue};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq)]
pub struct UnlimitedStorageArguments {
    pub len: u16,
}

/// Build Simplicity arguments for storage program.
#[must_use]
pub fn build_unlimited_storage_arguments(args: &UnlimitedStorageArguments) -> Arguments {

    Arguments::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("LEN"),
            simplicityhl::Value::from(UIntValue::U16(u16::from(args.len))),
        ),
    ]))
}

impl simplicityhl_core::Encodable for UnlimitedStorageArguments {}
