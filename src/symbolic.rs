//! Symbolic execution engine for WASM.

use foldhash::HashMap;
use miette::IntoDiagnostic;
use wasmparser::{Operator, ValType};

use crate::{
    check::Issue,
    parser::Program,
    typed::{FuncIndex, Loc, OpIndex},
};

pub fn execute<'a>(program: Program<'a>) {
    let func_indices = crate::check::find_exported_target_functions(&program);
    if func_indices.is_empty() {
        tracing::error!("Module defines no hooks");
    }
    for (export_name, func_index) in func_indices {
        match execute_from_func(&program, export_name, func_index) {
            Ok(issues) => {
                if issues.is_empty() {
                    eprintln!("NO ISSUES");
                } else {
                    for issue in issues {
                        eprintln!("ISSUE: {issue:?}");
                    }
                }
            }
            Err(e) => {
                tracing::error!("Error while running symbolic execution: {e:?}");
            }
        }
    }
}

#[tracing::instrument(
    skip(program, export_name, func_index),
    fields(program = program.name, target.name = export_name, target.index = %func_index))]
pub fn execute_from_func<'a>(
    program: &Program<'a>,
    export_name: &'a str,
    func_index: FuncIndex,
) -> miette::Result<Vec<Issue>> {
    tracing::debug!("running symbolic execution");

    tracing::trace!("Functions: {:?}", program.func_names);
    tracing::trace!("Function bodies: {:?}", program.func_bodies);

    let (sym_store, store_immut) = store_from_program(program)?;
    let mut executor = Executor {
        issues: vec![],
        state: State {
            stack: SymStack {
                values: vec![],
                frames: vec![],
            },
            store: sym_store,
        },
        pc: Loc {
            func_idx: func_index,
            op_idx: OpIndex(0),
        },
        thread: 0,
        solver: z3::Solver::new(),
    };

    executor.execute(&store_immut);

    // preconditions: for now, we assume no parameters to the function !!!

    Ok(executor.issues)
}

enum CtrlFlow {
    Cont(Loc),
    Exit,
}

struct Executor {
    issues: Vec<Issue>,
    state: State,
    pc: Loc,
    thread: u64,
    solver: z3::Solver,
}
impl Executor {
    pub fn execute(&mut self, store_immut: &StoreImmutable<'_>) {
        self.state
            .stack
            .frames
            .push(SymCtrlFrame::CallFrame(SymCallFrame {
                locals: store_immut.init_locals_for_func(self.pc.func_idx),
                next_pc: self.pc,
            }));
        loop {
            let op = store_immut.get_operator(self.pc);
            match self.dispatch_op(op, store_immut) {
                CtrlFlow::Cont(loc) => {
                    self.pc = loc;
                }
                CtrlFlow::Exit => break,
            }
        }
    }

    fn dead_thread_placeholder(&mut self) {
        //
    }

    fn dispatch_op(&mut self, op: &Operator<'_>, store_immut: &StoreImmutable<'_>) -> CtrlFlow {
        let mut control_flow: Option<CtrlFlow> = None;
        match op {
            // --- CONTROL OPERATIONS
            Operator::Unreachable => {
                // Execution trapped, this should not happen
                self.issues.push(Issue::Unreachable {
                    func: store_immut.funcs.get_func_debug_name(self.pc.func_idx),
                    op: self.pc.op_idx,
                });
                tracing::debug!(
                    "Thread {} encountered `unreachable` instruction, halting",
                    self.thread
                );
                // This thread is dead now
                self.dead_thread_placeholder();
                // incremental development process
            }
            Operator::Nop => {
                // Do nothing
            }
            Operator::Block { blockty } => todo!(),
            Operator::Loop { blockty } => todo!(),
            Operator::If { blockty } => todo!(),
            Operator::Else => todo!(),
            Operator::End => {
                // End is a pseudoinstructions symbolizing the end of a block, loop, if, or else
                // Alright, now the critical thing: which of these things is it ???

                let popped_frame = self
                    .state
                    .stack
                    .frames
                    .pop()
                    .expect("`end` operator: no frame to pop");
                match popped_frame {
                    SymCtrlFrame::CallFrame(call_frame) => {
                        control_flow = Some(if self.state.stack.frames.is_empty() {
                            tracing::debug!("Thread {} exited normally, halting", self.thread);
                            CtrlFlow::Exit
                        } else {
                            CtrlFlow::Cont(call_frame.next_pc)
                        });
                    }
                    SymCtrlFrame::Label(label) => {
                        todo!() // TODO
                    }
                }
            }
            Operator::Return => {
                todo!()
            }
            Operator::Br { relative_depth } => todo!(),
            Operator::BrIf { relative_depth } => todo!(),
            Operator::BrTable { targets } => todo!(),
            Operator::Call { function_index } => todo!(),
            Operator::CallIndirect {
                type_index: _,
                table_index: _,
            } => {
                self.issues.push(Issue::IndirectCall {
                    func: store_immut.funcs.get_func_debug_name(self.pc.func_idx),
                    op: self.pc.op_idx,
                });
                tracing::debug!(
                    "Thread {} encountered `call_indirect` instruction, halting",
                    self.thread
                );
                self.dead_thread_placeholder();
            }
            Operator::Drop => todo!(),
            Operator::Select => todo!(),

            // --- LOCALS
            Operator::LocalGet { local_index } => {
                let call_frame = self.state.stack.get_call_frame_mut().unwrap();
                let val = call_frame
                    .locals
                    .get(*local_index as usize)
                    .unwrap()
                    .clone();
                tracing::debug!("local.get {local_index:x} -> {val:?}");
                self.state.stack.values.push(val);
            }
            Operator::LocalSet { local_index } => {
                let val = self.state.stack.values.pop().unwrap();
                let call_frame = self.state.stack.get_call_frame_mut().unwrap();
                let prev = std::mem::replace(
                    call_frame.locals.get_mut(*local_index as usize).unwrap(),
                    val.clone(),
                );
                tracing::debug!("local.set {local_index:x} ({prev:?}) <- {val:?}");
            }
            Operator::LocalTee { local_index } => {
                let val = self.state.stack.values.last().unwrap().clone();
                let call_frame = self.state.stack.get_call_frame_mut().unwrap();
                let prev = std::mem::replace(
                    call_frame.locals.get_mut(*local_index as usize).unwrap(),
                    val.clone(),
                );
                tracing::debug!("local.tee {local_index:x} ({prev:?}) <- {val:?}");
            }

            // --- GLOBALS
            Operator::GlobalGet { global_index } => {
                let val = self
                    .state
                    .store
                    .globals
                    .values
                    .get(*global_index as usize)
                    .unwrap()
                    .clone();
                tracing::debug!("global.get {global_index:x} -> {val:?}");
                self.state.stack.values.push(val);
            }
            Operator::GlobalSet { global_index } => {
                let val = self.state.stack.values.pop().unwrap();
                let prev = std::mem::replace(
                    self.state
                        .store
                        .globals
                        .values
                        .get_mut(*global_index as usize)
                        .unwrap(),
                    val.clone(),
                );
                tracing::debug!("global.set {global_index:x} ({prev:?}) <- {val:?}");
            }

            // --- MEMORY LOAD/STORE
            Operator::I32Load { memarg } => {
                let addr = self.state.stack.values.pop().unwrap().into_int32().unwrap();
                assert!(2u32.pow(u32::from(memarg.align)).is_multiple_of(4));
                let addr_with_offset = &addr.ast + memarg.offset;
                let loads = self
                    .state
                    .store
                    .mems
                    .memories
                    .get_mut(memarg.memory as usize)
                    .unwrap()
                    .read(
                        &self.solver,
                        &addr_with_offset,
                        2usize.pow(u32::from(memarg.align)),
                        4,
                    );
                tracing::debug!(
                    "i32.load +{} <- {:?} ({:?})",
                    memarg.offset,
                    addr,
                    addr_with_offset
                );
                if let Some(loads) = loads {
                    assert!(!loads.is_empty());
                    for load in loads {
                        tracing::debug!("... -> @{:?} = {:?}", load.at, load.value);
                    }
                    todo!()
                } else {
                    tracing::error!("Can't prove access is in-bounds!");
                    self.issues.push(Issue::UnprovableAccess {});
                    self.dead_thread_placeholder();
                };
            }
            Operator::I64Load { memarg } => todo!(),
            Operator::I32Load8S { memarg } => todo!(),
            Operator::I32Load8U { memarg } => todo!(),
            Operator::I32Load16S { memarg } => todo!(),
            Operator::I32Load16U { memarg } => todo!(),
            Operator::I64Load8S { memarg } => todo!(),
            Operator::I64Load8U { memarg } => todo!(),
            Operator::I64Load16S { memarg } => todo!(),
            Operator::I64Load16U { memarg } => todo!(),
            Operator::I64Load32S { memarg } => todo!(),
            Operator::I64Load32U { memarg } => todo!(),
            Operator::I32Store { memarg } => {
                //
            }
            Operator::I64Store { memarg } => todo!(),
            Operator::I32Store8 { memarg } => todo!(),
            Operator::I32Store16 { memarg } => todo!(),
            Operator::I64Store8 { memarg } => todo!(),
            Operator::I64Store16 { memarg } => todo!(),
            Operator::I64Store32 { memarg } => todo!(),

            // --- MEMORY META
            Operator::MemorySize { mem } => todo!(),
            Operator::MemoryGrow { mem } => todo!(),

            // --- INTEGER OPS
            Operator::I32Const { value } => {
                tracing::debug!("i32.const {value:x}");
                self.state
                    .stack
                    .values
                    .push(SymValue::Int32(Int32::from_i32(*value)));
            }
            Operator::I64Const { value } => {
                tracing::debug!("i64.const {value:x}");
                self.state
                    .stack
                    .values
                    .push(SymValue::Int64(Int64::from_i64(*value)))
            }
            Operator::I32Eqz => todo!(),
            Operator::I32Eq => todo!(),
            Operator::I32Ne => todo!(),
            Operator::I32LtS => todo!(),
            Operator::I32LtU => todo!(),
            Operator::I32GtS => todo!(),
            Operator::I32GtU => todo!(),
            Operator::I32LeS => todo!(),
            Operator::I32LeU => todo!(),
            Operator::I32GeS => todo!(),
            Operator::I32GeU => todo!(),
            Operator::I64Eqz => todo!(),
            Operator::I64Eq => todo!(),
            Operator::I64Ne => todo!(),
            Operator::I64LtS => todo!(),
            Operator::I64LtU => todo!(),
            Operator::I64GtS => todo!(),
            Operator::I64GtU => todo!(),
            Operator::I64LeS => todo!(),
            Operator::I64LeU => todo!(),
            Operator::I64GeS => todo!(),
            Operator::I64GeU => todo!(),
            Operator::I32Clz => todo!(),
            Operator::I32Ctz => todo!(),
            Operator::I32Popcnt => todo!(),
            Operator::I32Add => {
                let v2 = self.state.stack.values.pop().unwrap().into_int32().unwrap();
                let v1 = self.state.stack.values.pop().unwrap().into_int32().unwrap();
                tracing::debug!("i32.add <- {v1:?} - {v2:?}");
                let ast = v1.ast + v2.ast;
                self.state.stack.values.push(SymValue::Int32(Int32 { ast }));
            }
            Operator::I32Sub => {
                let v2 = self.state.stack.values.pop().unwrap().into_int32().unwrap();
                let v1 = self.state.stack.values.pop().unwrap().into_int32().unwrap();
                tracing::debug!("i32.sub <- {v1:?} - {v2:?}");
                let ast = v1.ast - v2.ast;
                self.state.stack.values.push(SymValue::Int32(Int32 { ast }));
            }
            Operator::I32Mul => todo!(),
            Operator::I32DivS => todo!(),
            Operator::I32DivU => todo!(),
            Operator::I32RemS => todo!(),
            Operator::I32RemU => todo!(),
            Operator::I32And => todo!(),
            Operator::I32Or => todo!(),
            Operator::I32Xor => todo!(),
            Operator::I32Shl => todo!(),
            Operator::I32ShrS => todo!(),
            Operator::I32ShrU => todo!(),
            Operator::I32Rotl => todo!(),
            Operator::I32Rotr => todo!(),
            Operator::I64Clz => todo!(),
            Operator::I64Ctz => todo!(),
            Operator::I64Popcnt => todo!(),
            Operator::I64Add => todo!(),
            Operator::I64Sub => todo!(),
            Operator::I64Mul => todo!(),
            Operator::I64DivS => todo!(),
            Operator::I64DivU => todo!(),
            Operator::I64RemS => todo!(),
            Operator::I64RemU => todo!(),
            Operator::I64And => todo!(),
            Operator::I64Or => todo!(),
            Operator::I64Xor => todo!(),
            Operator::I64Shl => todo!(),
            Operator::I64ShrS => todo!(),
            Operator::I64ShrU => todo!(),
            Operator::I64Rotl => todo!(),
            Operator::I64Rotr => todo!(),
            Operator::I32WrapI64 => todo!(),
            Operator::I32TruncF32S => todo!(),
            Operator::I32TruncF32U => todo!(),
            Operator::I32TruncF64S => todo!(),
            Operator::I32TruncF64U => todo!(),
            Operator::I64ExtendI32S => todo!(),
            Operator::I64ExtendI32U => todo!(),
            Operator::I64TruncF32S => todo!(),
            Operator::I64TruncF32U => todo!(),
            Operator::I64TruncF64S => todo!(),
            Operator::I64TruncF64U => todo!(),
            Operator::I32ReinterpretF32 => todo!(),
            Operator::I64ReinterpretF64 => todo!(),
            Operator::I32Extend8S => todo!(),
            Operator::I32Extend16S => todo!(),
            Operator::I64Extend8S => todo!(),
            Operator::I64Extend16S => todo!(),
            Operator::I64Extend32S => todo!(),

            // --- MISCELLANEOUS
            // FIXME: sort these out
            Operator::RefEq => todo!(),
            Operator::StructNew { struct_type_index } => todo!(),
            Operator::StructNewDefault { struct_type_index } => todo!(),
            Operator::StructGet {
                struct_type_index,
                field_index,
            } => todo!(),
            Operator::StructGetS {
                struct_type_index,
                field_index,
            } => todo!(),
            Operator::StructGetU {
                struct_type_index,
                field_index,
            } => todo!(),
            Operator::StructSet {
                struct_type_index,
                field_index,
            } => todo!(),
            Operator::ArrayNew { array_type_index } => todo!(),
            Operator::ArrayNewDefault { array_type_index } => todo!(),
            Operator::ArrayNewFixed {
                array_type_index,
                array_size,
            } => todo!(),
            Operator::ArrayNewData {
                array_type_index,
                array_data_index,
            } => todo!(),
            Operator::ArrayNewElem {
                array_type_index,
                array_elem_index,
            } => todo!(),
            Operator::ArrayGet { array_type_index } => todo!(),
            Operator::ArrayGetS { array_type_index } => todo!(),
            Operator::ArrayGetU { array_type_index } => todo!(),
            Operator::ArraySet { array_type_index } => todo!(),
            Operator::ArrayLen => todo!(),
            Operator::ArrayFill { array_type_index } => todo!(),
            Operator::ArrayCopy {
                array_type_index_dst,
                array_type_index_src,
            } => todo!(),
            Operator::ArrayInitData {
                array_type_index,
                array_data_index,
            } => todo!(),
            Operator::ArrayInitElem {
                array_type_index,
                array_elem_index,
            } => todo!(),
            Operator::RefTestNonNull { hty } => todo!(),
            Operator::RefTestNullable { hty } => todo!(),
            Operator::RefCastNonNull { hty } => todo!(),
            Operator::RefCastNullable { hty } => todo!(),
            Operator::BrOnCast {
                relative_depth,
                from_ref_type,
                to_ref_type,
            } => todo!(),
            Operator::BrOnCastFail {
                relative_depth,
                from_ref_type,
                to_ref_type,
            } => todo!(),
            Operator::AnyConvertExtern => todo!(),
            Operator::ExternConvertAny => todo!(),
            Operator::RefI31 => todo!(),
            Operator::I31GetS => todo!(),
            Operator::I31GetU => todo!(),
            Operator::StructNewDesc { struct_type_index } => todo!(),
            Operator::StructNewDefaultDesc { struct_type_index } => todo!(),
            Operator::RefGetDesc { type_index } => todo!(),
            Operator::RefCastDescNonNull { hty } => todo!(),
            Operator::RefCastDescNullable { hty } => todo!(),
            Operator::BrOnCastDesc {
                relative_depth,
                from_ref_type,
                to_ref_type,
            } => todo!(),
            Operator::BrOnCastDescFail {
                relative_depth,
                from_ref_type,
                to_ref_type,
            } => todo!(),
            Operator::I32TruncSatF32S => todo!(),
            Operator::I32TruncSatF32U => todo!(),
            Operator::I32TruncSatF64S => todo!(),
            Operator::I32TruncSatF64U => todo!(),
            Operator::I64TruncSatF32S => todo!(),
            Operator::I64TruncSatF32U => todo!(),
            Operator::I64TruncSatF64S => todo!(),
            Operator::I64TruncSatF64U => todo!(),
            Operator::MemoryInit { data_index, mem } => todo!(),
            Operator::DataDrop { data_index } => todo!(),
            Operator::MemoryCopy { dst_mem, src_mem } => todo!(),
            Operator::MemoryFill { mem } => todo!(),
            Operator::TableInit { elem_index, table } => todo!(),
            Operator::ElemDrop { elem_index } => todo!(),
            Operator::TableCopy {
                dst_table,
                src_table,
            } => todo!(),
            Operator::TypedSelect { ty } => todo!(),
            Operator::TypedSelectMulti { tys } => todo!(),
            Operator::RefNull { hty } => todo!(),
            Operator::RefIsNull => todo!(),
            Operator::RefFunc { function_index } => todo!(),
            Operator::TableFill { table } => todo!(),
            Operator::TableGet { table } => todo!(),
            Operator::TableSet { table } => todo!(),
            Operator::TableGrow { table } => todo!(),
            Operator::TableSize { table } => todo!(),
            Operator::ReturnCall { function_index } => todo!(),
            Operator::ReturnCallIndirect {
                type_index,
                table_index,
            } => todo!(),
            Operator::MemoryDiscard { mem } => todo!(),
            Operator::RefI31Shared => todo!(),
            Operator::CallRef { type_index } => todo!(),
            Operator::ReturnCallRef { type_index } => todo!(),
            Operator::RefAsNonNull => todo!(),
            Operator::BrOnNull { relative_depth } => todo!(),
            Operator::BrOnNonNull { relative_depth } => todo!(),
            Operator::ContNew { cont_type_index } => todo!(),
            Operator::ContBind {
                argument_index,
                result_index,
            } => todo!(),
            Operator::Suspend { tag_index } => todo!(),
            Operator::Resume {
                cont_type_index,
                resume_table,
            } => todo!(),
            Operator::ResumeThrow {
                cont_type_index,
                tag_index,
                resume_table,
            } => todo!(),
            Operator::Switch {
                cont_type_index,
                tag_index,
            } => todo!(),
            Operator::I64Add128 => todo!(),
            Operator::I64Sub128 => todo!(),
            Operator::I64MulWideS => todo!(),
            Operator::I64MulWideU => todo!(),

            Operator::MemoryAtomicNotify { .. }
            | Operator::MemoryAtomicWait32 { .. }
            | Operator::MemoryAtomicWait64 { .. }
            | Operator::AtomicFence
            | Operator::I32AtomicLoad { .. }
            | Operator::I64AtomicLoad { .. }
            | Operator::I32AtomicLoad8U { .. }
            | Operator::I32AtomicLoad16U { .. }
            | Operator::I64AtomicLoad8U { .. }
            | Operator::I64AtomicLoad16U { .. }
            | Operator::I64AtomicLoad32U { .. }
            | Operator::I32AtomicStore { .. }
            | Operator::I64AtomicStore { .. }
            | Operator::I32AtomicStore8 { .. }
            | Operator::I32AtomicStore16 { .. }
            | Operator::I64AtomicStore8 { .. }
            | Operator::I64AtomicStore16 { .. }
            | Operator::I64AtomicStore32 { .. }
            | Operator::I32AtomicRmwAdd { .. }
            | Operator::I64AtomicRmwAdd { .. }
            | Operator::I32AtomicRmw8AddU { .. }
            | Operator::I32AtomicRmw16AddU { .. }
            | Operator::I64AtomicRmw8AddU { .. }
            | Operator::I64AtomicRmw16AddU { .. }
            | Operator::I64AtomicRmw32AddU { .. }
            | Operator::I32AtomicRmwSub { .. }
            | Operator::I64AtomicRmwSub { .. }
            | Operator::I32AtomicRmw8SubU { .. }
            | Operator::I32AtomicRmw16SubU { .. }
            | Operator::I64AtomicRmw8SubU { .. }
            | Operator::I64AtomicRmw16SubU { .. }
            | Operator::I64AtomicRmw32SubU { .. }
            | Operator::I32AtomicRmwAnd { .. }
            | Operator::I64AtomicRmwAnd { .. }
            | Operator::I32AtomicRmw8AndU { .. }
            | Operator::I32AtomicRmw16AndU { .. }
            | Operator::I64AtomicRmw8AndU { .. }
            | Operator::I64AtomicRmw16AndU { .. }
            | Operator::I64AtomicRmw32AndU { .. }
            | Operator::I32AtomicRmwOr { .. }
            | Operator::I64AtomicRmwOr { .. }
            | Operator::I32AtomicRmw8OrU { .. }
            | Operator::I32AtomicRmw16OrU { .. }
            | Operator::I64AtomicRmw8OrU { .. }
            | Operator::I64AtomicRmw16OrU { .. }
            | Operator::I64AtomicRmw32OrU { .. }
            | Operator::I32AtomicRmwXor { .. }
            | Operator::I64AtomicRmwXor { .. }
            | Operator::I32AtomicRmw8XorU { .. }
            | Operator::I32AtomicRmw16XorU { .. }
            | Operator::I64AtomicRmw8XorU { .. }
            | Operator::I64AtomicRmw16XorU { .. }
            | Operator::I64AtomicRmw32XorU { .. }
            | Operator::I32AtomicRmwXchg { .. }
            | Operator::I64AtomicRmwXchg { .. }
            | Operator::I32AtomicRmw8XchgU { .. }
            | Operator::I32AtomicRmw16XchgU { .. }
            | Operator::I64AtomicRmw8XchgU { .. }
            | Operator::I64AtomicRmw16XchgU { .. }
            | Operator::I64AtomicRmw32XchgU { .. }
            | Operator::I32AtomicRmwCmpxchg { .. }
            | Operator::I64AtomicRmwCmpxchg { .. }
            | Operator::I32AtomicRmw8CmpxchgU { .. }
            | Operator::I32AtomicRmw16CmpxchgU { .. }
            | Operator::I64AtomicRmw8CmpxchgU { .. }
            | Operator::I64AtomicRmw16CmpxchgU { .. }
            | Operator::I64AtomicRmw32CmpxchgU { .. } => {
                todo!("Atomics are not supported")
            }

            Operator::TryTable { .. }
            | Operator::Throw { .. }
            | Operator::ThrowRef
            | Operator::Try { .. }
            | Operator::Catch { .. }
            | Operator::Rethrow { .. }
            | Operator::Delegate { .. }
            | Operator::CatchAll => {
                todo!("Exceptions are not supported")
            }

            Operator::GlobalAtomicGet { .. }
            | Operator::GlobalAtomicSet { .. }
            | Operator::GlobalAtomicRmwAdd { .. }
            | Operator::GlobalAtomicRmwSub { .. }
            | Operator::GlobalAtomicRmwAnd { .. }
            | Operator::GlobalAtomicRmwOr { .. }
            | Operator::GlobalAtomicRmwXor { .. }
            | Operator::GlobalAtomicRmwXchg { .. }
            | Operator::GlobalAtomicRmwCmpxchg { .. }
            | Operator::TableAtomicGet { .. }
            | Operator::TableAtomicSet { .. }
            | Operator::TableAtomicRmwXchg { .. }
            | Operator::TableAtomicRmwCmpxchg { .. }
            | Operator::StructAtomicGet { .. }
            | Operator::StructAtomicGetS { .. }
            | Operator::StructAtomicGetU { .. }
            | Operator::StructAtomicSet { .. }
            | Operator::StructAtomicRmwAdd { .. }
            | Operator::StructAtomicRmwSub { .. }
            | Operator::StructAtomicRmwAnd { .. }
            | Operator::StructAtomicRmwOr { .. }
            | Operator::StructAtomicRmwXor { .. }
            | Operator::StructAtomicRmwXchg { .. }
            | Operator::StructAtomicRmwCmpxchg { .. }
            | Operator::ArrayAtomicGet { .. }
            | Operator::ArrayAtomicGetS { .. }
            | Operator::ArrayAtomicGetU { .. }
            | Operator::ArrayAtomicSet { .. }
            | Operator::ArrayAtomicRmwAdd { .. }
            | Operator::ArrayAtomicRmwSub { .. }
            | Operator::ArrayAtomicRmwAnd { .. }
            | Operator::ArrayAtomicRmwOr { .. }
            | Operator::ArrayAtomicRmwXor { .. }
            | Operator::ArrayAtomicRmwXchg { .. }
            | Operator::ArrayAtomicRmwCmpxchg { .. } => {
                todo!("Atomics are not supported");
            }

            Operator::F32Load { .. }
            | Operator::F64Load { .. }
            | Operator::F32Store { .. }
            | Operator::F64Store { .. }
            | Operator::F32Const { .. }
            | Operator::F64Const { .. }
            | Operator::F32Eq
            | Operator::F32Ne
            | Operator::F32Lt
            | Operator::F32Gt
            | Operator::F32Le
            | Operator::F32Ge
            | Operator::F64Eq
            | Operator::F64Ne
            | Operator::F64Lt
            | Operator::F64Gt
            | Operator::F64Le
            | Operator::F64Ge
            | Operator::F32Abs
            | Operator::F32Neg
            | Operator::F32Ceil
            | Operator::F32Floor
            | Operator::F32Trunc
            | Operator::F32Nearest
            | Operator::F32Sqrt
            | Operator::F32Add
            | Operator::F32Sub
            | Operator::F32Mul
            | Operator::F32Div
            | Operator::F32Min
            | Operator::F32Max
            | Operator::F32Copysign
            | Operator::F64Abs
            | Operator::F64Neg
            | Operator::F64Ceil
            | Operator::F64Floor
            | Operator::F64Trunc
            | Operator::F64Nearest
            | Operator::F64Sqrt
            | Operator::F64Add
            | Operator::F64Sub
            | Operator::F64Mul
            | Operator::F64Div
            | Operator::F64Min
            | Operator::F64Max
            | Operator::F64Copysign
            | Operator::F32ConvertI32S
            | Operator::F32ConvertI32U
            | Operator::F32ConvertI64S
            | Operator::F32ConvertI64U
            | Operator::F32DemoteF64
            | Operator::F64ConvertI32S
            | Operator::F64ConvertI32U
            | Operator::F64ConvertI64S
            | Operator::F64ConvertI64U
            | Operator::F64PromoteF32
            | Operator::F32ReinterpretI32
            | Operator::F64ReinterpretI64 => {
                // issues.push(Issue::FloatingPoint {
                //     func: store_immut.funcs.get_func_debug_name(pc.func_idx),
                //     op: pc.op_idx,
                // });
                todo!("Floating point is not supported")
            }
            unknown_op => {
                panic!("Unknown operator at {:?}: {unknown_op:?}", self.pc);
            }
        }

        control_flow.unwrap_or(CtrlFlow::Cont(Loc {
            op_idx: OpIndex(self.pc.op_idx.0 + 1),
            ..self.pc
        }))
    }
}

fn store_from_program<'a>(
    program: &Program<'a>,
) -> miette::Result<(SymStoreMutable, StoreImmutable<'a>)> {
    let global_values = program
        .globals
        .iter()
        .map(|global| {
            let ops_reader = global.init_expr.get_operators_reader();
            let mut ops_iter = ops_reader.into_iter();

            match ops_iter
                .next()
                .unwrap()
                .expect("failed to read operator from global initializer expression")
            {
                Operator::I32Const { value } => {
                    assert_eq!(ops_iter.next().unwrap().unwrap(), Operator::End);
                    assert!(ops_iter.next().is_none());
                    SymValue::Int32(Int32::from_i32(value))
                }
                x => {
                    panic!("wack does not support operator {x:?} in global initializer expression");
                }
            }
        })
        .collect();
    let memories = program
        .memories
        .iter()
        .map(|mem| SymMem {
            size: mem.initial as usize * 65536,
            stores: vec![],
        })
        .collect();
    let sym_store = SymStoreMutable {
        globals: SymGlobals {
            values: global_values,
        },
        mems: SymMems { memories },
        tables: SymTables {},
    };
    let mut store_immut = StoreImmutable {
        funcs: Funcs {
            import_count: program.imported_funcs.len(),
            locals: vec![],
            bodies: vec![],
            names: program
                .func_names
                .iter()
                .map(|(k, v)| (FuncIndex(*k), *v))
                .collect(),
        },
    };

    for func in program.func_bodies.iter() {
        // We need to get two pieces of information:
        //  1) what are the number and types of the locals
        //  2) what are the operators making up each function
        let mut locals = vec![];
        let mut locals_decompression_map = vec![];
        let mut total_locals = 0;
        for local in func.get_locals_reader().into_diagnostic()? {
            let (count, val_type) = local.into_diagnostic()?;
            locals.push((count, val_type));
            locals_decompression_map.push(total_locals);
            total_locals += count;
        }

        let mut ops = vec![];
        for op in func.get_operators_reader().into_diagnostic()? {
            let op = op.into_diagnostic()?;
            ops.push(op);
        }

        // Put these into the immutable store
        store_immut.funcs.locals.push(FuncLocalsDesc {
            compressed: locals,
            compressed_idx_to_decompressed_idx: locals_decompression_map,
        });
        store_immut.funcs.bodies.push(ops);
    }

    // TODO: symbolic store
    // TODO: data segments

    Ok((sym_store, store_immut))
}

// State we need to keep track of:
//  - stack (incl. call frames)
//  - store
// Okay, first: doing it the stupid way, with full state fork
// How do we treat constraints on memory?
//  Problem: mixed-size stuff.
//   - do accesses need to be aligned? NO lol oops
//   - Solution:
// How to track state on the stack?
//  1. treat __stack_pointer magically
//  2. alternatively: just fuck it and handle it normally?

struct FuncLocalsDesc {
    compressed: Vec<(u32, ValType)>,
    compressed_idx_to_decompressed_idx: Vec<u32>,
}
struct Funcs<'a> {
    import_count: usize,
    locals: Vec<FuncLocalsDesc>,
    bodies: Vec<Vec<Operator<'a>>>,
    names: HashMap<FuncIndex, &'a str>,
}
impl<'a> Funcs<'a> {
    pub fn get_func_debug_name(&self, idx: FuncIndex) -> String {
        self.names
            .get(&idx)
            .copied()
            .map(ToOwned::to_owned)
            .unwrap_or(format!("{idx}"))
    }
    pub fn get_func_info(&self, idx: FuncIndex) -> Option<(&FuncLocalsDesc, &[Operator<'a>])> {
        let idx = (idx.0 as usize).checked_sub(self.import_count)?;
        Some((&self.locals[idx], &&self.bodies[idx]))
    }
}
struct StoreImmutable<'a> {
    funcs: Funcs<'a>,
}
impl<'a> StoreImmutable<'a> {
    pub fn get_operator(&self, pc: Loc) -> &Operator<'a> {
        let (_locals, ops) = self
            .funcs
            .get_func_info(pc.func_idx)
            .expect("Pc out of range");
        ops.get(pc.op_idx.0 as usize).expect("Pc out of range")
    }
    pub fn init_locals_for_func(&self, func_index: FuncIndex) -> Vec<SymValue> {
        let (locals_desc, _body) = self
            .funcs
            .get_func_info(func_index)
            .expect("init_locals_for_func only works on functions that are defined in the module");
        let mut locals = vec![];
        for (count, val_type) in locals_desc.compressed.iter() {
            locals.extend(std::iter::repeat_n(
                SymValue::default_for_value_type(val_type),
                *count as usize,
            ));
        }
        locals
    }
}

#[derive(Debug, Clone)]
struct Int32 {
    ast: z3::ast::BV,
}
impl Int32 {
    pub fn from_i32(x: i32) -> Self {
        Self {
            ast: z3::ast::BV::from_i64(i64::from(x), 32),
        }
    }
}

#[derive(Debug, Clone)]
struct Int64 {
    ast: z3::ast::BV,
}
impl Int64 {
    pub fn from_i64(x: i64) -> Self {
        Self {
            ast: z3::ast::BV::from_i64(x, 64),
        }
    }
}

#[derive(Debug, Clone)]
enum SymValue {
    Int32(Int32),
    Int64(Int64),
    // FIXME: NO FLOAT SUPPORT
    // Float32 { ast: z3::ast::Float },
    // Float64 { ast: z3::ast::Float },
    Ref { ref_: () },
    RefNull,
    RefUninit,
    // Vec { t: () }
    // FIXME: NO SIMD SUPPORT
}
impl SymValue {
    pub fn into_int32(self) -> Result<Int32, Self> {
        match self {
            Self::Int32(z) => Ok(z),
            x => Err(x),
        }
    }
    pub fn into_int64(self) -> Result<Int64, Self> {
        match self {
            Self::Int64(z) => Ok(z),
            x => Err(x),
        }
    }
    pub fn default_for_value_type(val_type: &ValType) -> Self {
        match val_type {
            ValType::I32 => Self::Int32(Int32::from_i32(0)),
            ValType::I64 => Self::Int64(Int64::from_i64(0)),
            ValType::F32 | ValType::F64 => {
                todo!("Floating point not supported")
            }
            ValType::V128 => todo!("SIMD not supported"),
            ValType::Ref(ref_type) => {
                if ref_type.is_nullable() {
                    Self::RefNull
                } else {
                    Self::RefUninit
                }
            }
        }
    }
}
/// Activation record of an active function call
struct SymCallFrame {
    // return_arity: usize,
    // Note that non-primitive structures can only be passed by reference
    locals: Vec<SymValue>,
    next_pc: Loc,
}
struct Label {
    // TODO: labels
    t: (),
}
enum SymCtrlFrame {
    CallFrame(SymCallFrame),
    Label(Label),
}
struct SymStack {
    values: Vec<SymValue>,
    frames: Vec<SymCtrlFrame>,
    // FIXME: No exception support
}
impl SymStack {
    pub fn get_call_frame_mut(&mut self) -> Option<&mut SymCallFrame> {
        self.frames.iter_mut().rev().find_map(|x| match x {
            SymCtrlFrame::CallFrame(sym_call_frame) => Some(sym_call_frame),
            SymCtrlFrame::Label(_) => None,
        })
    }
}
struct SymGlobals {
    values: Vec<SymValue>,
}

// We use the same trick EXE and Klee used: holding coherent constraints over the entire memory
// space is a bit much, so instead we segment the memory space into "allocations" and then we do
// constraints at the level of individual allocations instead.
//
// Simplifying assumption:
//  - all accesses are naturally aligned (1/2/4/8)

struct SymStore {
    addr: z3::ast::BV,
    align: usize,
    size: usize,
    value: z3::ast::BV,
}
struct SymLoad {
    at: z3::ast::BV,
    value: z3::ast::BV,
}

struct SymMem {
    // Size, in bytes, of the linear memory
    size: usize,
    stores: Vec<SymStore>,
}
impl SymMem {
    fn bounds_check(&self, solver: &z3::Solver, addr: &z3::ast::BV, size: usize) -> bool {
        let end = addr + z3::ast::BV::from_u64(size as u64, addr.get_size());
        solver.assert(end.to_int(false).ge(addr.to_int(false)));
        solver.assert(
            end.to_int(false)
                .le(z3::ast::Int::from_u64(self.size as u64)),
        );
        match solver.check() {
            z3::SatResult::Unsat => {
                tracing::error!("Out of bounds access!");
                false
            }
            z3::SatResult::Unknown => {
                tracing::error!("Cannot prove in-bounds access!");
                false
            }
            z3::SatResult::Sat => true,
        }
    }

    pub fn write(
        &mut self,
        solver: &z3::Solver,
        addr: z3::ast::BV,
        value: z3::ast::BV,
        align: usize,
        size: usize,
    ) -> bool {
        if !self.bounds_check(solver, &addr, size) {
            return false;
        }

        self.stores.push(SymStore {
            addr,
            size,
            align,
            value,
        });

        true
    }

    pub fn read(
        &self,
        solver: &z3::Solver,
        addr: &z3::ast::BV,
        align: usize,
        size: usize,
    ) -> Option<Vec<SymLoad>> {
        // TODO: constraints!!
        if !self.bounds_check(solver, addr, size) {
            return None;
        }
        let mut results = vec![];
        for store in self.stores.iter().rev() {
            // TODO: find all stores in self.stores that
            //        1) aren't overwritten by later stores, and
            //        2) *could* cover part of this read
            // ... this is kinda screwy, is there a better way to do this?
        }
        if results.is_empty() {
            // memory was not previously written, so we treat it as zero
            tracing::debug!("no previous writes to {addr:?}");
            results.push(SymLoad {
                at: addr.clone(),
                value: z3::ast::BV::from_u64(0, size.try_into().unwrap()),
            });
        }
        Some(results)
    }
}

struct SymMems {
    memories: Vec<SymMem>,
}
struct SymTables {
    //
}
struct SymStoreMutable {
    // FIXME: NO EXCEPTION SUPPORT
    // tags: (),
    globals: SymGlobals,
    mems: SymMems,
    tables: SymTables,
    // Funcs, Datas, Elems, structs (?), arrays (?), exceptions (?) are not mutable (?)
}

pub struct State {
    stack: SymStack,
    store: SymStoreMutable,
}
