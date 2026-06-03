#![allow(clippy::module_inception)]
#[allow(clippy::all)]
mod gen;

pub mod references;

pub use crate::common::ast::IdedExpr as Expression;

mod macros;
mod parse;
#[allow(non_snake_case)]
mod parser;

pub use parser::*;
pub use references::ExpressionReferences;

// Relay fork (G4): re-export the synthetic `transformMap` step-function name so
// the comprehension evaluator (objects.rs) can special-case it without
// hard-coding the literal string in two places.
pub use macros::MAP_INSERT;
