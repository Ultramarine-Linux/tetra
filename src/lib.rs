//! Tetra: a modular host agent and recipe renderer for the Ultramarine Server
//! web control plane.
//!
//! The crate is organized into two top-level modules:
//!
//! - [`agent`]: the dispatcher, its feature-gated modules, and the transports
//!   (vsock, WSS) that expose the same command-envelope protocol to the
//!   dashboard or control plane.
//! - [`catalog`]: the recipe engine that renders YAML recipes into Quadlet and
//!   companion files using Tera templates.
//!
//! The binary in `src/main.rs` wires these into CLI subcommands.

pub mod agent;
pub mod auth;
pub mod catalog;
pub mod enrollment;
pub mod prelude;
pub mod types;

/// [`serde_json::json!`] with field shorthands.
///
/// # Examples
/// ```
/// # use tetra::jsonf;
/// struct X { foo: String }
/// let x = X { foo: String::from("bar") };
/// let b = 1;
/// assert_eq!(jsonf!{ "a": 1, b }, serde_json::json!({ "a": 1, "b": 1 }));
/// assert_eq!(jsonf!{ x.foo }, serde_json::json!({ "foo": x.foo }));
/// ```
#[macro_export]
macro_rules! jsonf {
    ($($fs:tt)*) => { $crate::__jsonf_inner!([$($fs)*]) };
}

#[macro_export]
macro_rules! __jsonf_inner {
    ([] $($done:tt)*) => { ::serde_json::json!({ $($done)* }) }; // finish
    ([$a:literal: [$($b:tt)*] $(,$($tt:tt)*)?] $($done:tt)*) => {
        $crate::__jsonf_inner!([$($($tt)*)?] $($done)* $a: [$($b)*],)
    }; // ╰─ match field: […]
    ([$a:literal: { $($b:tt)* } $(,$($tt:tt)*)?] $($done:tt)*) => {
        $crate::__jsonf_inner!([$($($tt)*)?] $($done)* $a: { $($b)* },)
    }; // ╰─ match field: { … }
    ([$a:literal: $b:expr $(,$($tt:tt)*)?] $($done:tt)*) => {
        $crate::__jsonf_inner!([$($($tt)*)?] $($done)* $a: $b,)
    }; // ╰─ match field: expr
    ([$head:ident $(. $field:ident)* $(,$($tt:tt)*)?] $($done:tt)*) => {
        $crate::__jsonf_inner!(@last [$head $(. $field)*] [$head $(. $field)*] [$($($tt)*)?] $($done)*)
    }; // ╰─ match obj.field
    (@last [$f:ident . $($rest:tt)+] $e:tt $tt:tt $($done:tt)*) => {
        $crate::__jsonf_inner!(@last [$($rest)+] $e $tt $($done)*)
    }; // @last: extracting last field
    (@last [$f:ident] [$($e:tt)+] [$($tt:tt)*] $($done:tt)*) => {
        $crate::__jsonf_inner!([$($tt)*] $($done)* stringify!($f): $($e)+,)
    }; // @last: form tt
}
