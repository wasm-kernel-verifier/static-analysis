use std::{
    collections::{BTreeMap, VecDeque},
    fmt::{self, Formatter},
    ops::{Bound, IntoBounds},
    range::Range,
    sync::{Arc, Mutex},
};

use foldhash::{HashMap, HashMapExt as _};
use wasmparser::{Operator, ValType};
use z3::{
    SatResult, Solvable, Solver,
    ast::{Ast, BV, Bool},
};

use crate::{
    check::Issue,
    parser::Program,
    typed::{FuncIdx, Loc, OpIdx},
};

pub fn execute<'a>(program: Program<'a>) {
    let target_funcs = crate::check::find_exported_target_functions(&program);
    if target_funcs.is_empty() {
        tracing::error!("Module defines no hooks");
        return;
    }
    for (exported_func_name, func_idx) in target_funcs {
        tracing::info!("Starting symbolic execution from function `{exported_func_name}`");
        let mut manager = PathManager {
            path_count: 1,
            retired_paths: BTreeMap::new(),
            frontier: VecDeque::new(),
            cfg_max_fanout: 128,
            next_path_id: 2,
        };
        let static_store = StaticStore {
            funcs: Funcs {
                import_count: todo!(),
                locals: todo!(),
                bodies: todo!(),
                names: todo!(),
            },
        };
        let globals = program
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
                        panic!(
                            "wack does not support operator {x:?} in global initializer expression"
                        );
                    }
                }
            })
            .collect();
        let memories = program
            .memories
            .iter()
            .map(|mem| SymMem {
                size: mem.initial as usize * 65536,
                stores: HashMap::from_iter(
                    [(
                        StoreId(0),
                        ConcStore {
                            addr: 0usize,
                            align: 4,
                            size: mem.initial as usize,
                            value: BV::from_u64(0, mem.initial as u32),
                        },
                    )]
                    .into_iter(),
                ),
                ind: vec![StoreId(0); mem.initial as usize],
                next_store_id: 1,
            })
            .collect();
        let path = Path {
            id: PathId(1),
            parent: PathId(0), // nonexistent
            pc: Loc {
                func_idx,
                op_idx: OpIdx(0),
            },
            stack: SymStack {
                max_depth: 128,
                values: vec![],
                frames: vec![],
            },
            globals: vec![],
            memories: vec![],
            tables: (),
            constraints: BTreeMap::new(),
            solver: z3::Solver::new(),
            issues: IssueSet(Arc::new(Mutex::new(IssueSetInner {
                unsafe_operations: HashMap::new(),
                unverifiable_operations: HashMap::new(),
            }))),
        };
        manager.frontier.push_back(path);

        loop {}
    }
}

struct StaticStore<'a> {
    funcs: Funcs<'a>,
}
impl<'a> StaticStore<'a> {
    /// Get the operator at the function and operator index specified in `loc`.
    ///
    /// # Panics
    ///
    /// Panics if function or operator index is out of range, or the function index refers to an
    /// imported function.
    pub fn get_operator(&self, loc: Loc) -> &Operator<'a> {
        let (_locals, ops) = self
            .funcs
            .get_func_info(loc.func_idx)
            .expect("Func index out of range or an import");
        ops.get(loc.op_idx.0 as usize).expect("Pc out of range")
    }

    pub fn get_initial_locals_for_func(&self, func_idx: FuncIdx) -> Vec<SymValue> {
        let (locals_desc, _body) = self
            .funcs
            .get_func_info(func_idx)
            .expect("Func index out of range or an import");
        let mut locals = vec![];
        for (count, val_type) in locals_desc.compressed.iter() {
            locals.extend(std::iter::repeat_n(
                SymValue::default_for_val_type(*val_type),
                *count as usize,
            ));
        }
        locals
    }
}

struct FuncLocalsDesc {
    compressed: Vec<(u32, ValType)>,
    compressed_idx_to_decompressed_idx: Vec<u32>,
}
struct Funcs<'a> {
    import_count: usize,
    locals: Vec<FuncLocalsDesc>,
    bodies: Vec<Vec<Operator<'a>>>,
    names: HashMap<FuncIdx, &'a str>,
}
impl<'a> Funcs<'a> {
    pub fn get_func_debug_name(&self, idx: FuncIdx) -> String {
        self.names
            .get(&idx)
            .copied()
            .map(ToOwned::to_owned)
            .unwrap_or(format!("{idx}"))
    }
    pub fn get_func_info(&self, idx: FuncIdx) -> Option<(&FuncLocalsDesc, &[Operator<'a>])> {
        let idx = (idx.0 as usize).checked_sub(self.import_count)?;
        Some((&self.locals[idx], &&self.bodies[idx]))
    }
}

// --- VALUES -------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Int32 {
    ast: BV,
}
impl Int32 {
    pub fn from_i32(x: i32) -> Self {
        Self {
            ast: BV::from_i64(i64::from(x), 32),
        }
    }
}

#[derive(Debug, Clone)]
struct Int64 {
    ast: BV,
}
impl Int64 {
    pub fn from_i64(x: i64) -> Self {
        Self {
            ast: BV::from_i64(i64::from(x), 64),
        }
    }
}

#[derive(Debug, Clone)]
enum SymValue {
    Int32(Int32),
    Int64(Int64),
    Ref { ref_: () },
    RefNull,
    RefUninit,
    // FIXME: NO SIMD SUPPORT + NO FLOAT SUPPORT
}
impl SymValue {
    fn into_int32(self) -> Result<Int32, Self> {
        match self {
            Self::Int32(z) => Ok(z),
            x => Err(x),
        }
    }
    fn into_int64(self) -> Result<Int64, Self> {
        match self {
            Self::Int64(z) => Ok(z),
            x => Err(x),
        }
    }
    fn default_for_val_type(val_type: ValType) -> Self {
        match val_type {
            ValType::I32 => Int32::from_i32(0).into(),
            ValType::I64 => Int64::from_i64(0).into(),
            ValType::F32 | ValType::F64 | ValType::V128 => unimplemented!(),
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
impl From<Int32> for SymValue {
    fn from(value: Int32) -> Self {
        Self::Int32(value)
    }
}
impl From<Int64> for SymValue {
    fn from(value: Int64) -> Self {
        Self::Int64(value)
    }
}

// --- MEMORY -------------------------------------------------------------------------------------

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct StoreId(u64);

#[derive(Debug, Clone)]
struct SymMem {
    size: usize,
    stores: HashMap<StoreId, ConcStore>,
    ind: Vec<StoreId>,
    next_store_id: u64,
}
impl SymMem {
    fn push(&mut self, value: ConcStore) {
        let store_id = StoreId(self.next_store_id);
        self.next_store_id = self.next_store_id.strict_add(1);
        for i in value.addr..value.addr + value.size {
            self.ind[i] = store_id;
        }
        self.stores.insert(store_id, value);
    }
}
#[derive(Debug, Clone)]
struct ConcStore {
    addr: usize,
    align: usize,
    size: usize,
    value: z3::ast::BV,
}
impl ConcStore {
    fn intersect(&self, addr: u32, size: usize) -> Option<Range<usize>> {
        let self_range = self.addr..self.addr + self.size;
        let other_range = addr as usize..addr as usize + size;
        if self_range.end <= other_range.start || other_range.end <= self_range.start {
            None
        } else {
            let (Bound::Included(start), Bound::Excluded(end)) = self_range.intersect(other_range)
            else {
                panic!("intersection failed: expected included/excluded");
            };
            Some(Range { start, end })
        }
    }
}

// --- PATH MANAGER -------------------------------------------------------------------------------

struct PathManager {
    path_count: usize,
    retired_paths: BTreeMap<PathId, Path>,
    frontier: VecDeque<Path>,

    next_path_id: u32,

    cfg_max_fanout: usize,
}
impl PathManager {
    pub fn fork_and_push<'pm, 'p>(&'pm mut self, path: &'p Path) -> &'pm mut Path {
        let path2 = path.clone();
        self.frontier.push_back_mut(path2)
    }
    pub fn max_fanout(&self) -> usize {
        self.cfg_max_fanout
    }
}

// --- PATH ---------------------------------------------------------------------------------------

#[derive(Debug)]
struct IssueSetInner {
    unsafe_operations: HashMap<Loc, Vec<(PathId, Issue)>>,
    unverifiable_operations: HashMap<Loc, Vec<(PathId, Issue)>>,
}
#[derive(Debug, Clone)]
struct IssueSet(Arc<Mutex<IssueSetInner>>);
impl IssueSet {
    fn tag_unsafe(&self, op: Loc, path_id: PathId, issue: Issue) {
        let mut g = self.0.lock().unwrap();
        g.unsafe_operations
            .entry(op)
            .or_insert(vec![])
            .push((path_id, issue));
    }
    fn tag_unverifiable(&self, op: Loc, path_id: PathId, issue: Issue) {
        let mut g = self.0.lock().unwrap();
        g.unverifiable_operations
            .entry(op)
            .or_insert(vec![])
            .push((path_id, issue));
    }
}

/// Used to signify that the execution of a path could not continue because of a trap.
enum SafetyError {
    Trap,
    Unproven,
}

#[derive(Debug, Clone)]
struct Path {
    id: PathId,
    // TODO: do these as incremental updates on persistent stores to reduce state explosion
    parent: PathId,

    pc: Loc,

    stack: SymStack,
    globals: Vec<SymValue>,
    memories: Vec<SymMem>,
    tables: (),

    constraints: BTreeMap<LocalConstraintId, z3::ast::Bool>,
    solver: z3::Solver,

    issues: IssueSet,
}
enum Control {
    Go(Loc),
    Next,
    Trap,
    Exit,
}
enum ControlState {
    Running,
    Trapped,
    Terminated,
}
impl Path {
    /// Returns `true` if the path has terminated
    pub fn step_path(
        &mut self,
        static_store: &StaticStore<'_>,
        manager: &mut PathManager,
    ) -> ControlState {
        let op = static_store.get_operator(self.pc);
        match self.dispatch_operator(op, static_store, manager) {
            Control::Go(loc) => {
                self.pc = loc;
                ControlState::Running
            }
            Control::Next => {
                self.pc = self.pc.next();
                ControlState::Running
            }
            Control::Trap => ControlState::Trapped,
            Control::Exit => ControlState::Terminated,
        }
    }

    #[tracing::instrument(skip(self, op, static_store, manager), fields(path = %self.id))]
    pub fn dispatch_operator(
        &mut self,
        op: &Operator<'_>,
        static_store: &StaticStore<'_>,
        manager: &mut PathManager,
    ) -> Control {
        let control: Control;

        match op {
            // --- ADMINISTRATIVE
            Operator::Unreachable => {
                tracing::debug!("unreachable: at {loc}, trapping.", loc = self.pc);
                // trap!
                control = Control::Trap;
            }
            Operator::Nop => {
                tracing::debug!("nop: at {loc}", loc = self.pc);
                control = Control::Next;
            }

            // --- LOCALS
            Operator::LocalGet { local_index } => {
                let call_frame = self.stack.last_call_frame();
                let val = call_frame.local(*local_index).clone();
                tracing::debug!("local.get {local_index:x}: -> {val:?}");
                self.stack.push_value(val);
                control = Control::Next;
            }
            Operator::LocalSet { local_index } => {
                let val = self.stack.pop_value();
                let call_frame = self.stack.last_call_frame_mut();
                let prev = std::mem::replace(call_frame.local_mut(*local_index), val.clone());
                tracing::debug!("local.set {local_index:x}: <- {val:?} | old={prev:?}");
                control = Control::Next;
            }
            Operator::LocalTee { local_index } => {
                let val = self.stack.last_value().clone();
                let call_frame = self.stack.last_call_frame_mut();
                let prev = std::mem::replace(call_frame.local_mut(*local_index), val.clone());
                tracing::debug!("local.tee {local_index:x}: <- {val:?} | old={prev:?}");
                control = Control::Next;
            }

            // --- GLOBALS
            Operator::GlobalGet { global_index } => {
                let val = self.globals[*global_index as usize].clone();
                tracing::debug!("global.get {global_index:x}: -> {val:?}");
                self.stack.push_value(val);
                control = Control::Next;
            }
            Operator::GlobalSet { global_index } => {
                let val = self.stack.pop_value();
                let prev =
                    std::mem::replace(&mut self.globals[*global_index as usize], val.clone());
                tracing::debug!("global.set {global_index:x}: <- {val:?} | old={prev:?}");
                control = Control::Next;
            }

            // --- MEMORY LOAD/STORE
            Operator::I32Load { memarg } => {
                let addr = self.stack.pop_value().into_int32().unwrap();
                let addr_with_offset = &addr.ast + memarg.offset;
                let align = 2usize.pow(u32::from(memarg.align));
                tracing::debug!(
                    "i32.load {}:+{} /{}/{}: <- {addr:?}",
                    memarg.memory,
                    memarg.offset,
                    align,
                    2usize.pow(u32::from(memarg.max_align)),
                );
                let concrete_addresses = self.concretize_addr(
                    memarg.memory as usize,
                    &addr_with_offset,
                    4usize,
                    align,
                    manager.max_fanout(),
                );
                match concrete_addresses {
                    Ok(concrete_addresses) => {
                        // it was possible to prove that every possible concretization of this
                        // address was in-bounds
                        tracing::trace!("... # of concretizations = {}", concrete_addresses.len());
                        for addr in concrete_addresses {
                            let val = self.read_concrete(memarg.memory as usize, addr, 4usize);
                            tracing::trace!("... -> @{addr:x} = {val:?}");
                        }
                        control = Control::Next;
                        todo!()
                    }

                    // ----------------------------------------------------------------------------
                    // HUGE TODO : PROPERLY HANDLE THESE CASES IN THE HYBRID VERIFICATION MODE
                    // HUGE TODO : PROPERLY HANDLE THESE CASES IN THE HYBRID VERIFICATION MODE
                    // HUGE TODO : PROPERLY HANDLE THESE CASES IN THE HYBRID VERIFICATION MODE
                    // ---------------------------------------------------------------------------
                    Err(SafetyError::Unproven) => {
                        // it was not possible to prove that every possible concretization of this
                        // address was in-bounds
                        tracing::error!(
                            "... given the current path constraints, it was not possible to prove that every possible concretization of the expression {addr:?} is in-bounds"
                        );
                        control = Control::Trap;
                        todo!()
                    }
                    Err(SafetyError::Trap) => {
                        // it was proven that there exists a concretization of this address that is
                        // out-of-bounds, and thus this access is unsafe (note that this may be too
                        // conservative: it's possible for this to be a false positive resulting
                        // from an underspecification regime - TODO: how to handle that case?)
                        tracing::error!(
                            "... given the current path constraints, there is a concretization of the expression {addr:?} is out-of-bounds"
                        );
                        control = Control::Trap;
                        todo!()
                    }
                }
            }

            x => {
                tracing::error!("Unsupported instruction: {x:?}");
                // pretend we ran into a trap <-<
                control = Control::Trap;
            }
        }

        control
    }

    pub fn write_concrete(
        &mut self,
        memory: usize,
        addr: u32,
        align: usize,
        size: usize,
        value: BV,
    ) {
        let _prev = self.memories.get_mut(memory).unwrap().push(ConcStore {
            addr: addr as usize,
            align,
            size,
            value,
        });
    }

    pub fn read_concrete(&self, memory: usize, addr: u32, size: usize) -> BV {
        let mut bytes = vec![];
        let mut i = addr as usize;
        while i < (addr as usize + size) {
            let store_id = self.memories[memory].ind[i];
            let store = &self.memories[memory].stores[&store_id];
            let isect = store.intersect(addr, size).unwrap();
            bytes.push(
                store
                    .value
                    // extract is inclusive
                    .extract(isect.end as u32 * 8 - 1, isect.start as u32 * 8),
            );
            i += isect.end - isect.start;
        }
        bytes
            .into_iter()
            .reduce(|a, b| a.concat(b))
            .unwrap()
            // because we might be concat-ing bits of stores that were previously split apart
            // TODO: ablation bench
            .simplify()
    }

    pub fn concretize_addr(
        &self,
        memory: usize,
        addr: &BV,
        size: usize,
        align: usize,
        max_fanout: usize,
    ) -> Result<Vec<u32>, SafetyError> {
        let span = tracing::debug_span!(
            "concretizing address {memory}:{addr:?}, align={align} size={size}"
        );
        let _entered = span.enter();
        let result = self.solver.check();
        tracing::debug!(
            "address concretization SMT statistics: {:?}",
            self.solver.get_statistics()
        );
        match result {
            SatResult::Unsat => {
                tracing::error!("Failed to concretize address: path constraints unsatisfiable");
                return Err(SafetyError::Trap);
            }
            SatResult::Unknown => {
                tracing::error!("Failed to concretize address: path constraints not proven");
                return Err(SafetyError::Unproven);
            }
            SatResult::Sat => {
                let mut concretized = vec![];
                for conc_addr in self.solver.solutions(addr, true) {
                    tracing::trace!("concrete: {conc_addr:?}");
                    if concretized.len() >= max_fanout {
                        tracing::error!(
                            "Concretization fanout hit limit at {max_fanout}, aborting"
                        );
                        return Err(SafetyError::Unproven);
                    }
                    let addr32 = u32::try_from(conc_addr.as_u64().unwrap()).unwrap();
                    if (addr32 as usize).is_multiple_of(align) {
                        tracing::error!(
                            "Unaligned memory access on Mem#{memory} @{addr32:08x} for align {align}"
                        );
                        return Err(SafetyError::Trap);
                    }
                    let memory_size = self.memories[memory].size;
                    if (addr32 as usize + size) > memory_size {
                        tracing::error!(
                            "Memory access out of bounds on Mem#{memory} @{addr32:08x}:{size:x} overflows {memory_size:x}"
                        );
                        return Err(SafetyError::Trap);
                    }
                    // aligned, in-bounds, and within the fanout factor
                    concretized.push(addr32);
                }
                Ok(concretized)
            }
        }
    }
}

// --- STACK --------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SymStack {
    max_depth: usize,
    values: Vec<SymValue>,
    frames: Vec<SymFrame>,
}
#[derive(Debug, Clone)]
struct SymCallFrame {
    locals: Vec<SymValue>,
    next_pc: Loc,
}
impl SymCallFrame {
    pub fn local(&self, local_idx: u32) -> &SymValue {
        self.locals.get(local_idx as usize).unwrap()
    }
    pub fn local_mut(&mut self, local_idx: u32) -> &mut SymValue {
        self.locals.get_mut(local_idx as usize).unwrap()
    }
}
#[derive(Debug, Clone)]
enum SymFrame {
    CallFrame(SymCallFrame),
    Label(()),
}
impl SymStack {
    fn last_call_frame_mut(&mut self) -> &mut SymCallFrame {
        self.frames
            .iter_mut()
            .rev()
            .find_map(|x| match x {
                SymFrame::CallFrame(frame) => Some(frame),
                SymFrame::Label(()) => None,
            })
            .expect("last_call_frame_mut() called with no call frames in the control stack")
    }
    fn last_call_frame(&self) -> &SymCallFrame {
        self.frames
            .iter()
            .rev()
            .find_map(|x| match x {
                SymFrame::CallFrame(frame) => Some(frame),
                SymFrame::Label(()) => None,
            })
            .expect("last_call_frame() called with no call frames in the control stack")
    }

    fn pop_value(&mut self) -> SymValue {
        self.values
            .pop()
            .expect("pop_value() called with no values in the value stack")
    }
    fn last_value(&self) -> &SymValue {
        self.values
            .last()
            .expect("pop_value() called with no values in the value stack")
    }
    fn push_value(&mut self, val: impl Into<SymValue>) {
        assert!(
            self.values.len() >= self.max_depth,
            "push_value() called with full stack"
        );
        self.values.push(val.into());
    }
}

// --- NEWTYPES -----------------------------------------------------------------------------------

/// The identifier of a particular execution [`Path`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct PathId(u32);
impl fmt::Display for PathId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "path!{}", self.0)
    }
}

/// The identifier of a constraint within the implicit context of some [`Path`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct LocalConstraintId(u32);

/// The absolute identifier of a constraint.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct ConstraintId(PathId, LocalConstraintId);
impl fmt::Display for ConstraintId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "constraint:{}!{}", self.0, self.1.0)
    }
}
