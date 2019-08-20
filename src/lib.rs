
#![allow(dead_code, non_camel_case_types, unused_unsafe, unused_variables)]
#![allow(non_upper_case_globals, non_snake_case, unused_imports)]
#![allow(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy))]

#[macro_use]
pub extern crate wayland_sys as sys;

#[macro_use]
extern crate bitflags;

pub mod client {
    include!(concat!(env!("OUT_DIR"), "/client.rs"));
}
/*
pub mod server {
    include!(concat!(env!("OUT_DIR"), "/server.rs"));
}
*/
