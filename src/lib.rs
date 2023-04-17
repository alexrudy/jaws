#![doc = include_str!("../README.md")]
//!
//! # Examples
//!
//! Creating a JWT with some registered and some custom claims:
//! ```rust
#![doc = include_str!("../examples/simple-jwt.rs")]
//! ```

pub mod algorithms;
pub mod b64data;
pub mod claims;

#[cfg(feature = "fmt")]
pub mod fmt;

pub mod jose;
pub mod key;
mod numeric_date;
pub mod token;
