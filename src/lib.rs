// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/*!
  Contains definitions and constants used in the wire format. This is the
  source of truth for the codes used in the serialization, their values and
  sizes.
*/
pub mod proto;

/**
  Contains models and struct definitions for the objects exchanged in requests and
  responses. Some objects reuse types defined in proto for certain fields. E.g. the type of a
  route. These types could be readily be used by the dataplane.
*/
pub mod objects;

/**
  Contains the message types and traits and utilities to create them. These types are used for
  the implementation of the wire format in Rustland.
*/
pub mod msg;

/**
  Contains the actual implementation of the wire format --i.e. encoding and decoding of messages--
  in rust, and the objects exchanged. This is through trait "Wire".
*/
pub mod wire;

/*
  Contains tests for the rustland implementation
*/
#[cfg(test)]
mod tests;

/*
  Logging initialization
*/
pub mod log;

/*
 Sock utils
*/
pub mod socks;
