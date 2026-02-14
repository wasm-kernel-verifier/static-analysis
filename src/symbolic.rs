//! Symbolic execution engine for WASM.

use crate::parser::Program;

pub fn execute<'a>(_program: Program<'a>) {
    //
}

// State we need to keep track of:
//  - WASM stack (incl. call frames)
//  - memories
//  - globals
//
//
