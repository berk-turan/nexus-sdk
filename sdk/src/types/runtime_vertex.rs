//! Wrapper around `nexus_workflow::dag::RuntimeVertex` type. This struct
//! contains the vertex name as [`crate::types::TypeName`] and the type of
//! the vertex.
//!
//! - [`RuntimeVertex::Plain`] only contains the vertex name.
//! - [`RuntimeVertex::WithIterator`] variant contains the data about
//!   which iteration of the vertex is being executed and what is the max number
//!   of iterations.

use {
    crate::types::*,
    serde::{Deserialize, Serialize},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "_variant_name")]
pub enum RuntimeVertex {
    Plain {
        vertex: TypeName,
    },
    WithIterator {
        vertex: TypeName,
        #[serde(
            deserialize_with = "deserialize_sui_u64",
            serialize_with = "serialize_sui_u64"
        )]
        iteration: u64,
        #[serde(
            deserialize_with = "deserialize_sui_u64",
            serialize_with = "serialize_sui_u64"
        )]
        out_of: u64,
    },
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_plain() {
        let vertex = RuntimeVertex::Plain {
            vertex: TypeName {
                name: "vertex_a".to_string(),
            },
        };

        let json = serde_json::to_string(&vertex).unwrap();

        assert_eq!(
            json,
            r#"{"_variant_name":"Plain","vertex":{"name":"vertex_a"}}"#,
        );
    }

    #[test]
    fn test_deserialize_plain() {
        let json = r#"{
            "_variant_name": "Plain",
            "vertex": { "name": "vertex_b" }
        }"#;
        let vertex: RuntimeVertex = serde_json::from_str(json).unwrap();
        match vertex {
            RuntimeVertex::Plain { vertex } => {
                assert_eq!(
                    vertex,
                    TypeName {
                        name: "vertex_b".to_string()
                    }
                );
            }
            _ => panic!("Expected Plain variant"),
        }
    }

    #[test]
    fn test_serialize_with_iterator() {
        let vertex = RuntimeVertex::WithIterator {
            vertex: TypeName {
                name: "vertex_c".to_string(),
            },
            iteration: 5,
            out_of: 10,
        };
        let json = serde_json::to_string(&vertex).unwrap();
        assert_eq!(
            json,
            r#"{"_variant_name":"WithIterator","vertex":{"name":"vertex_c"},"iteration":"5","out_of":"10"}"#
        );
    }

    #[test]
    fn test_deserialize_with_iterator() {
        let json = r#"{
            "_variant_name": "WithIterator",
            "vertex": { "name": "vertex_d" },
            "iteration": "7",
            "out_of": "15"
        }"#;
        let vertex: RuntimeVertex = serde_json::from_str(json).unwrap();
        match vertex {
            RuntimeVertex::WithIterator {
                vertex,
                iteration,
                out_of,
            } => {
                assert_eq!(
                    vertex,
                    TypeName {
                        name: "vertex_d".to_string()
                    }
                );
                assert_eq!(iteration, 7);
                assert_eq!(out_of, 15);
            }
            _ => panic!("Expected WithIterator variant"),
        }
    }
}
