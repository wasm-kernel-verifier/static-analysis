use std::fmt::{self, Display, Formatter};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct FuncIdx(pub u32);
impl Display for FuncIdx {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Func#{}", self.0)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct OpIdx(pub u32);
impl Display for OpIdx {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Op#{}", self.0)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Loc {
    pub func_idx: FuncIdx,
    pub op_idx: OpIdx,
}
impl Loc {
    pub fn next(self) -> Self {
        let Self { func_idx, op_idx } = self;
        Self {
            func_idx,
            op_idx: OpIdx(op_idx.0.strict_add(1)),
        }
    }
}
impl Display for Loc {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Func#{}:Op#{}", self.func_idx, self.op_idx)
    }
}
