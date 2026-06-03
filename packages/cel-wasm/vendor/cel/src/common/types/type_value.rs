// Relay fork (G3): the trait-object (`dyn Val`) representation of a CEL TYPE
// value.
//
// CEL has first-class type values: `type(1)` evaluates to the `int` type, the
// type identifiers (`int`, `uint`, `double`, `bool`, `string`, `bytes`, `list`,
// `map`, `null_type`, `type`) are themselves type values, and a type value is
// comparable by NAME (`type(1) == int` is true; `type(1) == uint` is false).
//
// cel 0.13 carries a compile-time `Type<'a>` notion (see `mod.rs`) but the
// runtime `Value` enum (objects.rs) and the `dyn Val` interpreter world have no
// value that *is* a type. This is that value. It mirrors how the other concrete
// `Val` implementors (e.g. `CelNull`, `CelBool`) are structured: a small struct
// that reports its `get_type()` and a name-based `equals`.
//
// The runtime type of a type value is itself `type` (the meta-type), so
// `get_type()` returns `TYPE_TYPE`. That makes `type(type(1))` resolve to the
// `type` type value. Equality is by the canonical cel-go runtime type NAME
// (`vv.TypeName()` in cel-go), e.g. "int", "google.protobuf.Timestamp", "type".

use crate::common::types::{Type, TYPE_TYPE};
use crate::common::value::Val;
use std::sync::Arc;

/// A CEL type value, identified by its canonical runtime type name.
#[derive(Clone, Debug)]
pub struct TypeValue {
    name: Arc<str>,
}

impl TypeValue {
    /// Construct a type value from its canonical cel-go runtime type name.
    pub fn new(name: impl Into<Arc<str>>) -> Self {
        TypeValue { name: name.into() }
    }

    /// The canonical runtime type name this value denotes (e.g. "int",
    /// "google.protobuf.Timestamp", "type").
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The name as a shared `Arc<str>` (used to build the runtime `Value::Type`).
    pub fn name_arc(&self) -> Arc<str> {
        self.name.clone()
    }
}

impl Val for TypeValue {
    fn get_type(&self) -> Type<'_> {
        // The runtime type of a type value is the meta-type `type`.
        TYPE_TYPE
    }

    fn equals(&self, other: &dyn Val) -> bool {
        // Two type values are equal iff they name the same CEL type. A type
        // value never equals a non-type value (a downcast to TypeValue fails).
        match other.downcast_ref::<TypeValue>() {
            Some(other) => self.name == other.name,
            None => false,
        }
    }

    fn clone_as_boxed(&self) -> Box<dyn Val> {
        Box::new(self.clone())
    }
}
