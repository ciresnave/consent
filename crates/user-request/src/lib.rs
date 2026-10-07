// SPDX-License-Identifier: MIT OR Apache-2.0
//! `user-request`: ask a person to approve something, through a channel that
//! can be swapped (Windows Hello first; SMS and push designed for), and get
//! back a grant the APPROVER chose. CireSnave, 2026-10-04 (board item 121):
//! "a separate \"user-request\" crate ... Windows Hello, SMS requests, push
//! requests, etc. ... code requesting something from a user could use them
//! interchangeably".
//!
//! ⚠️ Stops ACCIDENTS, like with-secret (WITH-SECRET-DESIGN.md §3): any process
//! running as the same Windows user can drive the same APIs.

pub mod channel;
pub mod consent;
pub mod dpapi;
pub mod hello;
pub mod locate;
pub mod request;
pub mod store;

pub use channel::{prompt_text, Channel, HelloChannel, Outcome, PushChannel, SmsChannel};
pub use consent::{Consent, ConsentOutcome};
pub use request::{Approval, Grant, KindId, MaxGrant, Request, Requester, Scope, Unrepresentable};
