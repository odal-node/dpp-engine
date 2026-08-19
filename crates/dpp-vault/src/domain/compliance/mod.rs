//! Compliance strategies this node registers on top of the Apache-2.0 defaults.

mod calc_battery;

pub use calc_battery::CalcBatteryStrategy;

#[cfg(test)]
mod tests;
