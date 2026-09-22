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
    ([$e:expr $(,$($tt:tt)*)?] $($done:tt)*) => { ::preinterpret::preinterpret! {
        $crate::__jsonf_inner!(@last [[!raw! $e]] [$e $(, $($tt)*)?] $($done)*)
    } }; // ╰─ match obj.field
    (@last [$f:ident . $($stuff:tt)+] [$e:expr $(,$($tt:tt)*)?] $($done:tt)*) => {
        $crate::__jsonf_inner!(@last [$($stuff)+] [$e $(, $($tt)*)?] $($done)*)
    }; // @last: extracting last field
    (@last [$f:ident] [$e:expr $(,$($tt:tt)*)?] $($done:tt)*) => { ::preinterpret::preinterpret! {
        $crate::__jsonf_inner!([$($($tt)*)?] $($done)* [!string! $f]: $e,)
    } }; // @last: form tt
}

/// Helper for adding flags to a vec `args`.
///
/// # Usage
/// `flag!(args payload: system [shell] ["--home-dir" home]);` will:
/// - add `--system` if `payload.system` is true
/// - add `--shell {payload.shell}` if `payload.shell.is_some()`
/// - add `--home-dir {home}` if `payload.home.is_some()`
#[macro_export]
macro_rules! flag {
    ($args:ident $payload:ident:$($idk:tt)+) => {
        $($args.extend(flag!(@$payload $idk));)+
    };
    (@$payload:ident [$field:ident]) => {
        $payload.$field.into_iter().flat_map(|$field| [stringify!(--$field).to_owned(), $field])
    };
    (@$payload:ident [$s:literal $field:ident]) => {
        $payload.$field.into_iter().flat_map(|$field| [$s.to_owned(), $field])
    };
    (@$payload:ident $field:ident) => {
        $payload.$field.then(|| stringify!(--$field).to_owned())
    };
    (@$payload:ident $field:ident($e:expr)) => {
        $payload.$field.then(|| $e)
    };
}
