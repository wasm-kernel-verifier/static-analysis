use wasmparser::ExternalKind;

use crate::{
    parser::Program,
    typed::{FuncIdx, OpIdx},
};

pub fn find_exported_target_functions<'a>(program: &Program<'a>) -> Vec<(&'a str, FuncIdx)> {
    program
        .exports
        .iter()
        .filter_map(|export| {
            if export.name.starts_with("hook") {
                if matches!(export.kind, ExternalKind::Func) {
                    return Some((export.name, FuncIdx(export.index)));
                } else {
                    tracing::error!(
                        "Exported item `{}` is a {:?}, expected a Func",
                        export.name,
                        export.kind
                    );
                }
            }
            None
        })
        .collect()
}

// #[derive(Debug, thiserror::Error, miette::Diagnostic)]
// pub enum Issue {
//     #[error("Cannot disprove the existence of a nonterminating cycle in the call graph: {}",
//         funcs.iter().map(AsRef::as_ref).intersperse(" -> ").collect::<String>(),
//     )]
//     NonterminatingCycle { funcs: Vec<String> },
//     #[error("Discovered `call[_ref]_indirect` operator in `{func}`: {op}")]
//     IndirectCall { func: String, op: OpIdx },
//     // #[error("Discovered floating point operator in `{func}`: {op}")]
//     // FloatingPoint { func: String, op: OpIndex },
//     #[error("Cannot prove loop termination for loop in `{func}`: {op}")]
//     NonterminatingLoop { func: String, op: OpIdx },
//     #[error("Reached `unreachable` operator in `{func}`: `{op}`")]
//     Unreachable { func: String, op: OpIdx },
//     #[error("Out-of-bounds memory access to offset {offset} in memory#{memory}")]
//     OobAccess { memory: usize, offset: usize },
//     #[error("Unaligned access in memory#{memory} at offset#{offset}, min_align={min_align}")]
//     UnalignedAccess {
//         memory: usize,
//         offset: usize,
//         min_align: usize,
//     },
//     #[error("Couldn't prove access in-bounds")]
//     UnprovableAccess {
//         //
//     },
// }

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum Issue {
    #[error("Unsatisfiable path constraints")]
    PathUnsat,
    #[error("Unproven path constraints")]
    PathUnproven,
    #[error("Access fanout")]
    AccessFanout,
    #[error("Loop fanout")]
    LoopFanout,
    #[error("Access was not proven to be safe (aligned and in-bounds)")]
    AccessNotProvablySafe,
    #[error(
        "Access is not aligned (expected mask {expected_alignment:08x}, got address {addr:08x})"
    )]
    UnalignedAccess {
        expected_alignment: usize,
        addr: u32,
    },
    #[error(
        "Access is out-of-bounds on memory #{memory}; {addr:08x} + {size:08x} >= {memory_size:08x}"
    )]
    OutOfBoundsAccess {
        memory: usize,
        memory_size: usize,
        addr: u32,
        size: usize,
    },
}
