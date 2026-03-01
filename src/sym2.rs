use std::{
    collections::{BTreeMap, VecDeque, hash_map::Entry},
    fmt::{self, Formatter},
    hash::{BuildHasher, Hash},
    ops::{Bound, IntoBounds},
    range::Range,
    sync::{Arc, Mutex},
};

use foldhash::{HashMap, HashMapExt as _, HashSet, HashSetExt as _};
use miette::IntoDiagnostic as _;
use wasmparser::{ConstExpr, FuncType, Operator, ValType};
use z3::{
    SatResult, Solvable,
    ast::{Ast, BV},
};

use crate::{
    check::Issue,
    parser::Program,
    typed::{FuncIdx, Loc, OpIdx, TypeIdx},
};

fn resolve_const_expr(expr: &ConstExpr) -> i32 {
    let ops_reader = expr.get_operators_reader();
    let mut ops_iter = ops_reader.into_iter();

    match ops_iter
        .next()
        .unwrap()
        .expect("failed to read operator from global initializer expression")
    {
        Operator::I32Const { value } => {
            assert_eq!(ops_iter.next().unwrap().unwrap(), Operator::End);
            assert!(ops_iter.next().is_none());
            return value;
        }
        x => {
            panic!("wack does not support operator {x:?} in constant expression");
        }
    }
}

fn build_world<'a>(
    program: &Program<'a>,
) -> miette::Result<(StaticStore<'a>, Vec<SymValue>, Vec<SymMem>)> {
    let mut static_store = StaticStore {
        funcs: Funcs {
            import_count: program.imported_funcs.len(),
            locals: vec![],
            bodies: vec![],
            names: program
                .func_names
                .iter()
                .map(|(k, v)| (FuncIdx(*k), *v))
                .collect(),
            types: program.func_types.iter().map(|t| TypeIdx(*t)).collect(),
        },
        types: program.types.clone(),
    };
    let globals: Vec<_> = program
        .globals
        .iter()
        .map(|global| {
            let value = resolve_const_expr(&global.init_expr);
            SymValue::Int32(Int32::from_i32(value))
        })
        .collect();
    let mut memories: Vec<_> = program
        .memories
        .iter()
        .map(|mem| {
            let size = mem.initial as usize * 65536;
            SymMem {
                size,
                stores: BTreeMap::from_iter(
                    [(
                        StoreId(0),
                        ConcStore {
                            addr: 0usize,
                            align: 4,
                            size,
                            value: BV::from_u64(0, size as u32),
                        },
                    )]
                    .into_iter(),
                ),
                ind: vec![StoreId(0); size],
                next_store_id: 1,
            }
        })
        .collect();
    for data in &program.data_segments {
        match &data.kind {
            wasmparser::DataKind::Passive => { /* no action required */ }
            wasmparser::DataKind::Active {
                memory_index,
                offset_expr,
            } => {
                let offset = resolve_const_expr(offset_expr);
                for (i, b) in data.data.iter().enumerate() {
                    let addr = offset as usize + i;
                    let conc_store = ConcStore {
                        addr,
                        align: 1,
                        size: 1,
                        value: BV::from_u64(u64::from(*b), 8),
                    };
                    tracing::trace!("data segment: pushing {conc_store:?}");
                    memories[*memory_index as usize].push(conc_store);
                }
            }
        }
    }

    for func in program.func_bodies.iter() {
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
        static_store.funcs.locals.push(FuncLocalsDesc {
            compressed: locals,
            compressed_idx_to_decompressed_idx: locals_decompression_map,
        });
        static_store.funcs.bodies.push(ops);
    }

    Ok((static_store, globals, memories))
}

pub fn execute<'a>(program: Program<'a>, extra_funcs: HashSet<String>) -> miette::Result<()> {
    let target_funcs = crate::check::find_exported_target_functions(&program, extra_funcs);
    if target_funcs.is_empty() {
        tracing::error!("Module defines no hooks");
        miette::bail!("no hooks defined in WASM module");
    }

    println!(
        "\tWASM program defines {} hooks: {}",
        target_funcs.len(),
        target_funcs
            .iter()
            .map(|(n, _)| *n)
            .intersperse(", ")
            .collect::<String>()
    );

    let (static_store, globals, memories) = build_world(&program)?;

    for (exported_func_name, func_idx) in target_funcs {
        tracing::info!("Starting symbolic execution from function `{exported_func_name}`");
        let mut manager = PathManager {
            path_count: 1,
            retired_paths: BTreeMap::new(),
            frontier: VecDeque::new(),
            cfg_max_fanout: 128,
            cfg_max_loop_iters: 10,
            next_path_id: 2,
            path_hashes: HashSet::new(),
        };
        let issues = IssueSet(Arc::new(Mutex::new(IssueSetInner {
            unsafe_operations: HashMap::new(),
            unverifiable_operations: HashMap::new(),
        })));
        let mut path = Path {
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
            globals: globals.clone(),
            memories: memories.clone(),
            tables: (),
            constraints: BTreeMap::new(),
            solver: z3::Solver::new(),
            issues: issues.clone(),
            loop_counts: HashMap::new(),
        };
        path.stack.frames.push(SymFrame::CallFrame(SymCallFrame {
            locals: static_store.get_initial_locals_for_func(func_idx),
            cont: Loc {
                func_idx: FuncIdx(u32::MAX),
                op_idx: OpIdx(u32::MAX),
            },
            value_mark: 0,
            arity: static_store.get_func_type(func_idx).results().len(),
        }));
        manager.frontier.push_back(path);

        let mut n_inst = 0;

        let t0 = std::time::Instant::now();
        'paths: loop {
            let Some(mut path) = manager.frontier.pop_front() else {
                break 'paths;
            };
            let control_state = path.step(&static_store, &mut manager);
            if manager.state_exists(&path) {
                tracing::debug!("{} reached previously explored state, terminating", path.id);
                manager.retired_paths.insert(path.id, path);
                continue;
            }
            n_inst += 1;
            match control_state {
                ControlState::Running => {
                    manager.frontier.push_back(path);
                }
                ControlState::Trapped(op) => {
                    issues.tag_unsafe(op, path.id, Issue::Trap {});
                }
                ControlState::Terminated => {
                    tracing::debug!("{} terminated", path.id)
                }
            }
        }
        let t1 = std::time::Instant::now();
        tracing::debug!("Finished exploring paths");
        let verdict = match issues.verdict() {
            Verdict::KnownSafe => "OK",
            Verdict::SafetyUnprovable => "WIBBLY WOBBLY",
            Verdict::KnownTraps => "ÜBERVERBOTEN",
        };

        eprintln!();
        eprintln!("========================================================");
        eprintln!("REPORT FOR {exported_func_name} ({func_idx})");
        eprintln!(
            "Ran {} instructions across {} paths in {:?}",
            n_inst,
            manager.next_path_id - 1,
            t1 - t0
        );
        eprintln!("Verdict: {verdict}");
        eprintln!();
        std::mem::forget(manager);
    } // 9184
    Ok(())
}

struct StaticStore<'a> {
    funcs: Funcs<'a>,
    types: Vec<FuncType>,
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

    pub fn get_func_type(&self, func_idx: FuncIdx) -> &FuncType {
        &self.types[self.funcs.types[func_idx.0 as usize].0 as usize]
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
    types: Vec<TypeIdx>,
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

#[derive(Debug, Clone, Hash)]
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

#[derive(Debug, Clone, Hash)]
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

#[derive(Debug, Clone, Hash)]
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

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct StoreId(u64);

#[derive(Debug, Clone, Hash)]
struct SymMem {
    size: usize,
    stores: BTreeMap<StoreId, ConcStore>,
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
#[derive(Debug, Clone, Hash)]
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
        // tracing::trace!("intersect: {self_range:?} vs. {other_range:?}");

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

// --- TODO ---
// Make all PathIds just the hash, make Paths immutable and incremental

// --- PATH MANAGER -------------------------------------------------------------------------------

struct PathManager {
    path_count: usize,
    retired_paths: BTreeMap<PathId, Path>,
    frontier: VecDeque<Path>,

    next_path_id: u32,

    cfg_max_fanout: usize,
    cfg_max_loop_iters: usize,
    path_hashes: HashSet<u64>,
}
impl PathManager {
    pub fn fork_and_push<'pm, 'p>(&'pm mut self, path: &'p Path) -> &'pm mut Path {
        let mut path2 = path.clone();
        path2.id = PathId(self.next_path_id);
        self.next_path_id += 1;
        self.frontier.push_back_mut(path2)
    }
    pub fn max_fanout(&self) -> usize {
        self.cfg_max_fanout
    }
    pub fn max_loop_iters(&self) -> usize {
        self.cfg_max_loop_iters
    }

    pub fn state_exists(&mut self, path: &Path) -> bool {
        let hash_state = foldhash::fast::FixedState::with_seed(0);
        let hash = hash_state.hash_one(path);
        let pre = self.path_hashes.contains(&hash);
        self.path_hashes.insert(hash);
        pre
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
    fn verdict(&self) -> Verdict {
        let g = self.0.lock().unwrap();
        if !g.unsafe_operations.is_empty() {
            Verdict::KnownTraps
        } else if !g.unverifiable_operations.is_empty() {
            Verdict::SafetyUnprovable
        } else {
            Verdict::KnownSafe
        }
    }
}
enum Verdict {
    KnownTraps,
    SafetyUnprovable,
    KnownSafe,
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

    loop_counts: HashMap<Loc, usize>,
}
impl std::hash::Hash for Path {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.parent.hash(state);
        self.pc.hash(state);
        self.stack.hash(state);
        self.globals.hash(state);
        self.memories.hash(state);
        self.tables.hash(state);
        self.constraints.hash(state);
        // self.solver.hash(state);
        // self.issues.hash(state);
        // self.loop_counts.hash(state);
    }
}

enum Control {
    Go(Loc),
    Next,
    Trap,
    Exit,
}
enum ControlState {
    Running,
    Trapped(Loc),
    Terminated,
}
impl Path {
    /// Step the path forward by one operator.
    pub fn step(
        &mut self,
        static_store: &StaticStore<'_>,
        manager: &mut PathManager,
    ) -> ControlState {
        let op = static_store.get_operator(self.pc);
        match self.dispatch_operator(op, static_store, manager) {
            Control::Go(loc) => {
                if loc.func_idx == FuncIdx(u32::MAX) && loc.op_idx == OpIdx(u32::MAX) {
                    ControlState::Terminated
                } else {
                    self.pc = loc;
                    ControlState::Running
                }
            }
            Control::Next => {
                self.pc = self.pc.next();
                ControlState::Running
            }
            Control::Trap => ControlState::Trapped(self.pc),
            Control::Exit => ControlState::Terminated,
        }
    }

    /// Implements the basic "branch" operation of WebAssembly. Discard the last `relative_depth`,
    /// label frames from the stack, take the arity `n` of the `relative_depth+1`'th label frame,
    /// pop the top `n` values from the stack, discard everything including and above the
    /// `relative_depth+1`'th label frame on the stack, and push the stored `n` values back on top
    /// of the stack.
    fn branch(&mut self, mut relative_depth: u32) -> Control {
        loop {
            // stack looks like:
            //
            //     | .... | (label) | XX discard XX | XX keep (arity) XX |
            //
            // then movement is the number of discarded values
            if relative_depth == 0 {
                let SymFrame::Label(label) = self.stack.frames.last().unwrap() else {
                    unimplemented!("handlers are not supported");
                };
                let movement = self.stack.values.len() - label.arity - label.value_mark;
                assert!(
                    movement.cast_signed() >= 0,
                    "number of values discarded by branch is negative"
                );
                let _ = self
                    .stack
                    .values
                    .drain(label.value_mark..label.value_mark + movement);
                tracing::trace!(
                    "removed {movement} values from the stack, kept topmost {}",
                    label.arity
                );
                break Control::Go(label.cont);
            } else {
                let frame = self.stack.frames.pop().unwrap();
                tracing::trace!("popped frame  = {frame:?}");
                let SymFrame::Label(_label) = frame else {
                    unimplemented!("handlers are not supported")
                };
            }

            relative_depth -= 1;
        }
    }

    fn ret(&mut self) -> Control {
        let popped_frame = self.stack.frames.pop().expect("no label/call frame to pop");
        match popped_frame {
            SymFrame::CallFrame(call_frame) => {
                let movement = self.stack.values.len() - call_frame.arity - call_frame.value_mark;
                assert!(
                    movement.cast_signed() >= 0,
                    "number of values discarded by branch is negative"
                );
                let _ = self
                    .stack
                    .values
                    .drain(call_frame.value_mark..call_frame.value_mark + movement);
                tracing::trace!(
                    "removed {movement} values from the stack, kept topmost {}",
                    call_frame.arity
                );
                Control::Go(call_frame.cont)
            }
            SymFrame::Label(_sym_label) => self.ret(),
        }
    }

    #[tracing::instrument(skip(self, op, static_store, manager), fields(path = %self.id))]
    fn dispatch_operator(
        &mut self,
        op: &Operator<'_>,
        static_store: &StaticStore<'_>,
        manager: &mut PathManager,
    ) -> Control {
        // Ensure that we can set the next instruction from anywhere, and that it will fail to
        // compile if not set or set multiple times
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
            Operator::Block { blockty } => {
                let arity = match blockty {
                    wasmparser::BlockType::Empty => 0,
                    wasmparser::BlockType::Type(_val_type) => 1,
                    wasmparser::BlockType::FuncType(_idx) => {
                        todo!()
                    }
                };

                let mut lookahead_pc = self.pc;
                let mut depth = 1;
                loop {
                    lookahead_pc = lookahead_pc.next();
                    let op = static_store.get_operator(lookahead_pc);
                    if matches!(
                        op,
                        Operator::Loop { .. } | Operator::Block { .. } | Operator::If { .. }
                    ) {
                        depth += 1;
                    }
                    if matches!(op, Operator::End) {
                        depth -= 1;
                        if depth == 0 {
                            // 好了，我們到來啦
                            break;
                        }
                    }
                }
                tracing::debug!("block 0->{arity} ---> {lookahead_pc}");
                self.stack.frames.push(SymFrame::Label(SymLabel {
                    cont: lookahead_pc,
                    arity,
                    value_mark: self.stack.values.len(),
                }));
                control = Control::Next;
            }
            Operator::Loop { blockty } => {
                let arity = match blockty {
                    wasmparser::BlockType::Empty => 0,
                    wasmparser::BlockType::Type(_val_type) => 1,
                    wasmparser::BlockType::FuncType(_idx) => {
                        // todo
                        todo!()
                    }
                };
                self.stack.frames.push(SymFrame::Label(SymLabel {
                    // we go one past the loop because our stack works differently from the one in
                    // the WASM stack
                    cont: self.pc.next(),
                    arity,
                    value_mark: self.stack.values.len(),
                }));
                let loop_count = match self.loop_counts.entry(self.pc) {
                    Entry::Occupied(mut occupied_entry) => {
                        *occupied_entry.get_mut() += 1;
                        if *occupied_entry.get() >= manager.max_loop_iters() {
                            tracing::error!(
                                "Reached maximum loop iterations for {}, trapping",
                                self.pc
                            );
                            control = Control::Trap;
                        } else {
                            control = Control::Next;
                        }
                        *occupied_entry.get()
                    }
                    Entry::Vacant(vacant_entry) => {
                        vacant_entry.insert(1);
                        control = Control::Next;
                        1
                    }
                };
                tracing::debug!("loop 0->{arity} @{loop_count}");
            }
            Operator::If { blockty } => {
                //
                todo!()
            }
            Operator::Else => {
                //
                todo!()
            }
            Operator::End => {
                let popped_frame = self.stack.frames.pop().expect("no label/call frame to pop");
                match popped_frame {
                    SymFrame::CallFrame(call_frame) => {
                        if self.stack.frames.is_empty() {
                            tracing::debug!("end . {} exited normally", self.id);
                            control = Control::Exit;
                        } else {
                            control = Control::Go(call_frame.cont);
                        }
                    }
                    SymFrame::Label(label) => {
                        tracing::debug!("end . exited block at {}", label.cont);
                        if let Some(count) = self.loop_counts.remove(&self.pc) {
                            tracing::trace!(
                                "... loop at {} terminated after {count} iterations",
                                label.cont
                            );
                        }
                        control = Control::Next;
                    }
                }
            }
            Operator::Return => {
                control = self.ret();
            }
            Operator::Br { relative_depth } => {
                tracing::debug!("br {relative_depth}");
                control = self.branch(*relative_depth);
            }
            Operator::BrIf { relative_depth } => {
                let cond = self.stack.pop_value().into_int32().unwrap();
                let sat_ne0 = {
                    self.solver.push();
                    self.solver.assert(cond.ast.ne(0));
                    let sat_ne = self.solver.check();
                    self.solver.pop(1);
                    sat_ne
                };
                let sat_eq0 = {
                    self.solver.push();
                    self.solver.assert(cond.ast.eq(0));
                    let sat_eq = self.solver.check();
                    self.solver.pop(1);
                    sat_eq
                };
                // Interpretation:
                // sat_ne | sat_eq |
                // ???    | UNSAT  | for all inputs, not equal
                // UNSAT  | ???    | for all inputs, equal
                // ???    | ???    | can't prove anything

                // Whatever the solver figured out, we're going to go forward with that as an
                // assumption, so no need to push() here
                tracing::debug!(
                    "br_if {relative_depth} <- {cond:?}, false = {sat_eq0:?}, true = {sat_ne0:?}"
                );
                match (sat_eq0, sat_ne0) {
                    (_, SatResult::Unsat) => {
                        tracing::trace!("<cond> is UNSAT, asserting !<cond>");
                        // For all inputs, cond == 0, so DO NOT BRANCH
                        self.solver.assert(cond.ast.eq(0));
                        control = Control::Next;
                    }
                    (SatResult::Unsat, _) => {
                        tracing::trace!("!<cond> is UNSAT, asserting <cond>");
                        // For all inputs, cond == 1, so DO BRANCH
                        self.solver.assert(cond.ast.ne(0));
                        control = self.branch(*relative_depth);
                    }
                    (_, _) => {
                        tracing::trace!("<cond> is INDET, forking");
                        // couldn't come to a conclusion, so we fork and:
                        //  - in the forked path, assume the branch isn't taken
                        //  - in the current path, assume the branch is taken
                        // both branches taken; first, handle the other path since we have to fork first
                        let clone = manager.fork_and_push(self);
                        clone.solver.assert(cond.ast.eq(0));
                        clone.pc = self.pc.next();

                        // Then, handle the current path
                        self.solver.assert(cond.ast.ne(0));
                        control = self.branch(*relative_depth);
                    }
                }
            }
            Operator::BrTable { targets } => {
                //
                todo!()
            }
            Operator::Call { function_index } => {
                //
                todo!()
            }
            Operator::CallIndirect { .. } => {
                tracing::error!("{} encountered `call_indrect`, halting", self.id);
                control = Control::Trap;
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
            Operator::I32Store { memarg } => {
                let val = self.stack.pop_value();
                let addr = self.stack.pop_value().into_int32().unwrap();
                let addr_with_offset = &addr.ast + memarg.offset;
                let align = 2usize.pow(u32::from(memarg.align));
                tracing::debug!(
                    "i32.store {}:+{} /{}/{}: <- @{addr:?} := {val:?}",
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
                        tracing::trace!("... # of concretizations = {}", concrete_addresses.len());
                        if let Some(&addr) = concrete_addresses.first() {
                            // Have to handle the other paths first, since they're cloned from the
                            // current state of `self`.
                            for addr in &concrete_addresses[1..] {
                                tracing::trace!("... |-> @{addr:x}");
                                let clone = manager.fork_and_push(self);
                                // Execute the instruction and move the PC forward;
                                clone.write_concrete(
                                    memarg.memory as usize,
                                    *addr,
                                    align,
                                    4usize,
                                    val.clone().into_int32().unwrap().ast,
                                );
                                clone.pc = clone.pc.next();
                            }
                            // Finally, continue the current path.
                            tracing::trace!("... ==> @{addr:x}");
                            self.write_concrete(
                                memarg.memory as usize,
                                addr,
                                align,
                                4usize,
                                val.clone().into_int32().unwrap().ast,
                            );
                            control = Control::Next;
                        } else {
                            panic!("No concretizations of address!");
                        }
                    }
                    Err(SafetyError::Unproven) => {
                        tracing::error!(
                            "... given the current path constraints, it was not possible to prove that every possible concretization of the expression {addr:?} is in-bounds"
                        );
                        todo!()
                    }
                    Err(SafetyError::Trap) => {
                        tracing::error!(
                            "... given the current path constraints, there is a concretization of the expression {addr:?} is out-of-bounds"
                        );
                        todo!()
                    }
                }
            }
            Operator::I32Load8U { memarg } => {
                let addr = self.stack.pop_value().into_int32().unwrap();
                let addr_with_offset = &addr.ast + memarg.offset;
                let align = 2usize.pow(u32::from(memarg.align));
                tracing::debug!(
                    "i32.load8u {}:+{} /{}/{}: <- {addr:?}",
                    memarg.memory,
                    memarg.offset,
                    align,
                    2usize.pow(u32::from(memarg.max_align))
                );
                let concrete_addresses = self.concretize_addr(
                    memarg.memory as usize,
                    &addr_with_offset,
                    1usize,
                    align,
                    manager.max_fanout(),
                );
                match concrete_addresses {
                    Ok(concrete_addresses) => {
                        // it was possible to prove that every possible concretization of this
                        // address was in-bounds
                        tracing::trace!("... # of concretizations = {}", concrete_addresses.len());
                        if let Some(&addr) = concrete_addresses.first() {
                            // Other paths before `self`
                            for addr in &concrete_addresses[1..] {
                                let val = self
                                    .read_concrete(memarg.memory as usize, *addr, 1usize)
                                    .zero_ext(24);
                                tracing::trace!("... |-> @{addr:x} = {val:?}");
                                // Push the value and move the PC forward
                                let clone = manager.fork_and_push(self);
                                clone.stack.push_value(Int32 { ast: val });
                                clone.pc = clone.pc.next();
                            }
                            let val = self
                                .read_concrete(memarg.memory as usize, addr, 1usize)
                                .zero_ext(24);
                            tracing::trace!("... ==> @{addr:x} = {val:?}");
                            self.stack.push_value(Int32 { ast: val });
                            control = Control::Next;
                        } else {
                            panic!("No concretizations of address!");
                        }
                    }
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
                        if let Some(&addr) = concrete_addresses.first() {
                            // Other paths before `self`
                            for addr in &concrete_addresses[1..] {
                                let val = self.read_concrete(memarg.memory as usize, *addr, 4usize);
                                tracing::trace!("... |-> @{addr:x} = {val:?}");
                                // Push the value and move the PC forward
                                let clone = manager.fork_and_push(self);
                                clone.stack.push_value(Int32 { ast: val });
                                clone.pc = clone.pc.next();
                            }
                            let val = self.read_concrete(memarg.memory as usize, addr, 4usize);
                            tracing::trace!("... ==> @{addr:x} = {val:?}");
                            self.stack.push_value(Int32 { ast: val });
                            control = Control::Next;
                        } else {
                            panic!("No concretizations of address!");
                        }
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

            Operator::I32Const { value } => {
                tracing::debug!("i32.const 0x{value:x}");
                self.stack.push_value(Int32::from_i32(*value));
                control = Control::Next;
            }
            Operator::I32Sub => {
                let c2 = self.stack.pop_value().into_int32().unwrap();
                let c1 = self.stack.pop_value().into_int32().unwrap();
                let res = Int32 {
                    ast: &c1.ast - &c2.ast,
                };
                tracing::debug!("i32.sub {c1:?} - {c2:?} -> {res:?}");
                self.stack.push_value(res);
                control = Control::Next;
            }
            Operator::I32Add => {
                let c2 = self.stack.pop_value().into_int32().unwrap();
                let c1 = self.stack.pop_value().into_int32().unwrap();
                let res = Int32 {
                    ast: &c1.ast + &c2.ast,
                };
                tracing::debug!("i32.add {c1:?} + {c2:?} -> {res:?}");
                self.stack.push_value(res);
                control = Control::Next;
            }
            Operator::I32Eq => {
                let c2 = self.stack.pop_value().into_int32().unwrap();
                let c1 = self.stack.pop_value().into_int32().unwrap();
                let res = Int32 {
                    ast: (&c1.ast.eq(&c2.ast)).ite(&BV::from_i64(1, 32), &BV::from_i64(0, 32)),
                };
                tracing::debug!("i32.eq {c1:?} == {c2:?} -> {res:?}");
                self.stack.push_value(res);
                control = Control::Next;
            }
            Operator::I32Ne => {
                let c2 = self.stack.pop_value().into_int32().unwrap();
                let c1 = self.stack.pop_value().into_int32().unwrap();
                let res = Int32 {
                    ast: (&c1.ast.ne(&c2.ast)).ite(&BV::from_i64(1, 32), &BV::from_i64(0, 32)),
                };
                tracing::debug!("i32.eq {c1:?} == {c2:?} -> {res:?}");
                self.stack.push_value(res);
                control = Control::Next;
            }
            Operator::I32And => {
                let c2 = self.stack.pop_value().into_int32().unwrap();
                let c1 = self.stack.pop_value().into_int32().unwrap();
                let res = Int32 {
                    ast: &c1.ast & &c2.ast,
                };
                tracing::debug!("i32.and {c1:?} & {c2:?} -> {res:?}");
                self.stack.push_value(res);
                control = Control::Next;
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
            // tracing::trace!("at addr {i:x} hit store {store_id:?}");
            if store_id.0 == 0 {
                // bytes.push(BV::from_i64(0, 8));
                // tracing::trace!("hit store 0, serving uninit");
                bytes.push(BV::fresh_const(format!("uninit_{i:06x}_").as_str(), 8));
                i += 1;
                continue;
            }
            let store = &self.memories[memory].stores[&store_id];
            let isect = store.intersect(addr, size).unwrap();
            let hi = isect.end as u32 * 8 - 1 - store.addr as u32 * 8;
            let lo = isect.start as u32 * 8 - store.addr as u32 * 8;
            // tracing::trace!(
            //     "read_concrete: isect={isect:?}, val of ({}), hi={hi},lo={lo}",
            //     store.size
            // );

            bytes.push(
                store
                    .value
                    // extract is inclusive
                    .extract(hi, lo),
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
        &mut self,
        memory: usize,
        addr: &BV,
        size: usize,
        align: usize,
        max_fanout: usize,
    ) -> Result<Vec<u32>, SafetyError> {
        let span = tracing::debug_span!(
            "concretizing address",
            memory = memory,
            addr = ?addr,
            align = align,
            size = size
        );
        let _entered = span.enter();
        let result = self.solver.check();
        tracing::debug!("SMT stats: {:?}", self.solver.get_statistics());
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
                self.solver.push();
                let mut solver_iter = SolverIterator {
                    solver: &mut self.solver,
                    ast: addr,
                    model_completion: true,
                };
                // for conc_addr in self.solver.solutions(addr, true) {
                while let Some(conc_addr) = solver_iter.next() {
                    tracing::trace!("concrete: {conc_addr:?}");
                    if concretized.len() >= max_fanout {
                        tracing::error!(
                            "Concretization fanout hit limit at {max_fanout}, aborting"
                        );
                        return Err(SafetyError::Unproven);
                    }
                    let addr32 = u32::try_from(conc_addr.as_u64().unwrap()).unwrap();
                    if !(addr32 as usize).is_multiple_of(align) {
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
                self.solver.pop(1);
                Ok(concretized)
            }
        }
    }
}

struct SolverIterator<'a, T> {
    solver: &'a mut z3::Solver,
    ast: T,
    model_completion: bool,
}

impl<'a, T: Solvable> Iterator for SolverIterator<'a, T> {
    type Item = T::ModelInstance;

    fn next(&mut self) -> Option<Self::Item> {
        match self.solver.check() {
            SatResult::Sat => {
                let model = self.solver.get_model()?;
                let instance = self.ast.read_from_model(&model, self.model_completion)?;
                let counterexample = self.ast.generate_constraint(&instance);
                self.solver.assert(counterexample);
                Some(instance)
            }
            _ => None,
        }
    }
}

// --- STACK --------------------------------------------------------------------------------------

#[derive(Debug, Clone, Hash)]
struct SymStack {
    max_depth: usize,
    values: Vec<SymValue>,
    frames: Vec<SymFrame>,
}
#[derive(Debug, Clone, Hash)]
struct SymCallFrame {
    locals: Vec<SymValue>,
    cont: Loc,
    value_mark: usize,
    arity: usize,
}
impl SymCallFrame {
    pub fn local(&self, local_idx: u32) -> &SymValue {
        self.locals.get(local_idx as usize).unwrap()
    }
    pub fn local_mut(&mut self, local_idx: u32) -> &mut SymValue {
        self.locals.get_mut(local_idx as usize).unwrap()
    }
}
#[derive(Debug, Clone, Hash)]
struct SymLabel {
    cont: Loc,
    arity: usize,
    value_mark: usize,
    // branch_consumes_label: bool,
}
#[derive(Debug, Clone, Hash)]
enum SymFrame {
    CallFrame(SymCallFrame),
    Label(SymLabel),
}
impl SymStack {
    fn last_call_frame_mut(&mut self) -> &mut SymCallFrame {
        self.frames
            .iter_mut()
            .rev()
            .find_map(|x| match x {
                SymFrame::CallFrame(frame) => Some(frame),
                SymFrame::Label(_label) => None,
            })
            .expect("last_call_frame_mut() called with no call frames in the control stack")
    }
    fn last_call_frame(&self) -> &SymCallFrame {
        self.frames
            .iter()
            .rev()
            .find_map(|x| match x {
                SymFrame::CallFrame(frame) => Some(frame),
                SymFrame::Label(_label) => None,
            })
            .expect("last_call_frame() called with no call frames in the control stack")
    }

    fn pop_value(&mut self) -> SymValue {
        self.values
            .pop()
            .expect("pop_value() called with no values in the value stack")
    }
    fn pop_values(&mut self, count: usize) -> Vec<SymValue> {
        (0..count)
            .into_iter()
            .map(|_| self.values.pop().unwrap())
            .collect()
    }
    fn last_value(&self) -> &SymValue {
        self.values
            .last()
            .expect("pop_value() called with no values in the value stack")
    }
    fn push_value(&mut self, val: impl Into<SymValue>) {
        assert!(
            self.values.len() < self.max_depth,
            "push_value() called with full stack ({}/{})",
            self.values.len(),
            self.max_depth
        );
        self.values.push(val.into());
    }
}

// --- NEWTYPES -----------------------------------------------------------------------------------

/// The identifier of a particular execution [`Path`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
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
