//! Vip is a Rust library for the Symantec VIP API.
//!
//! Usually, Symantec VIP is used to integrate MFA into your authentication workflow and might be used
//! in conjunction with some form of single sign-on (SSO). A typical workflow may require sending
//! a push notification to a device linked to a particular user, wait for the confirmation of the
//! push notification in order to generate a security code. This security code is used to construct
//! a valid SAML request. To generate both a valid security key and SAML request it is important to
//! use the same user agent during the execution of the authentication workflow.
//!
//! At the moment Vip only supports a very basic workflow for issueing a security code. Which means
//! that the tools deals with unknown devices only and the fall back to enetring a Symantec VIP code
//! manually is not supported yet.
//!
//! ### Examples
//! Please check out the code.
//!
//! # Installation
//! Add the following to your `Cargo.toml` file:
//! ```toml
//! [dependencies]
//! vip = { git = "https://github.com/mttrbit/vip-rs", branch = "main"}
//! ```
extern crate reqwest;
extern crate serde;
extern crate serde_json;

pub mod vip;
