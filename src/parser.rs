//! Parse WASM programs.

use std::ops::Deref;

use crate::typed::FuncIdx;
use foldhash::HashMap;
use miette::IntoDiagnostic;
use wasmparser::{
    Data, Element, Encoding, Export, FuncType, FunctionBody, Global, Import, KnownCustom,
    MemoryType, Parser, Table, TagType, TypeRef,
};

/// Static representation of a WASM program, with all the information we need to run symbolic
/// interpretation.
#[derive(Default)]
pub struct ProgramData<'a> {
    pub name: &'a str,
    pub dwarf_sections: Vec<(&'a str, &'a [u8])>,
    pub data_segments: Vec<Data<'a>>,
    pub func_types: Vec<u32>,
    pub func_bodies: Vec<FunctionBody<'a>>,
    pub globals: Vec<Global<'a>>,
    pub exports: Vec<Export<'a>>,
    pub elements: Vec<Element<'a>>,
    pub tags: Vec<TagType>,
    pub memories: Vec<MemoryType>,
    pub tables: Vec<Table<'a>>,
    pub imports: Vec<Import<'a>>,
    pub types: Vec<FuncType>,
    pub func_names: HashMap<u32, &'a str>,
}
pub struct Program<'a> {
    data: ProgramData<'a>,
    pub imported_funcs: Vec<usize>,
}
impl<'a> Deref for Program<'a> {
    type Target = ProgramData<'a>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}
impl<'a> Program<'a> {
    /// Get the name of the function referred to by `func_index`, if it exists in the `name`
    /// section of the module, otherwise return `None`.
    pub fn get_func_name(&self, func_index: FuncIdx) -> Option<&'a str> {
        self.func_names.get(&func_index.0).map(|x| *x)
    }

    /// Returns `Some` if the function at `func_index` was defined by the module, otherwise returns
    /// `None` if `func_index` refers to an imported function.
    ///
    /// # Panics
    ///
    /// Will panic if `func_index` does not refer to a function available in the module.
    pub fn get_func_body(&self, func_index: FuncIdx) -> Option<&FunctionBody<'a>> {
        (func_index.0 as usize)
            .checked_sub(self.imported_funcs.len())
            .map(|index| self.func_bodies.get(index).expect("FuncIndex out of range"))
    }
}
impl<'a> Program<'a> {
    pub fn from_program_data(data: ProgramData<'a>) -> Self {
        let imported_funcs: Vec<usize> = data
            .imports
            .iter()
            .enumerate()
            .filter_map(|(idx, import)| match import.ty {
                TypeRef::Func(_) | TypeRef::FuncExact(_) => Some(idx),
                _ => None,
            })
            .collect();
        Self {
            data,
            imported_funcs,
        }
    }
}

#[tracing::instrument(skip(program_bytes))]
pub fn parse_wasm<'a>(program_bytes: &'a [u8], name: &'a str) -> miette::Result<Program<'a>> {
    let parser = Parser::new(0);

    let mut program = ProgramData {
        name,
        ..Default::default()
    };

    for payload in parser.parse_all(program_bytes) {
        let payload = payload.into_diagnostic()?;
        match payload {
            wasmparser::Payload::Version {
                num,
                encoding,
                range: _,
            } => {
                miette::ensure!(
                    matches!(encoding, Encoding::Module),
                    "{name} is not a WASM module"
                );
                tracing::trace!("Version: {num}");
            }
            wasmparser::Payload::TypeSection(section) => {
                tracing::trace!("Encountered Type section");
                for ty in section.into_iter_err_on_gc_types() {
                    let func_ty = ty.into_diagnostic()?;
                    program.types.push(func_ty);
                }
            }
            wasmparser::Payload::ImportSection(section) => {
                tracing::trace!("Encountered Import section");
                for import in section.into_imports() {
                    program.imports.push(import.into_diagnostic()?);
                }
            }
            wasmparser::Payload::FunctionSection(section) => {
                tracing::trace!("Encountered Function section");
                for func_ty in section.into_iter_with_offsets() {
                    let (_func_ty_idx, func_ty) = func_ty.into_diagnostic()?;
                    program.func_types.push(func_ty);
                }
            }
            wasmparser::Payload::TableSection(section) => {
                tracing::trace!("Encountered Table section");
                for table in section.into_iter_with_offsets() {
                    let (_tbl_idx, table) = table.into_diagnostic()?;
                    program.tables.push(table);
                }
            }
            wasmparser::Payload::MemorySection(section) => {
                tracing::trace!("Encountered Memory section");
                for memory in section.into_iter_with_offsets() {
                    let (_mem_idx, memory) = memory.into_diagnostic()?;
                    program.memories.push(memory);
                }
            }
            wasmparser::Payload::TagSection(section) => {
                tracing::trace!("Encountered Tag section");
                for tag in section.into_iter_with_offsets() {
                    let (_tag_idx, tag) = tag.into_diagnostic()?;
                    program.tags.push(tag);
                }
            }
            wasmparser::Payload::GlobalSection(section) => {
                tracing::trace!("Encountered Global section");
                for global in section.into_iter_with_offsets() {
                    let (_gl_idx, global) = global.into_diagnostic()?;
                    program.globals.push(global);
                }
            }
            wasmparser::Payload::ExportSection(section) => {
                tracing::trace!("Encountered Export section");
                for export in section.into_iter_with_offsets() {
                    let (_ex_idx, export) = export.into_diagnostic()?;
                    program.exports.push(export);
                }
            }
            wasmparser::Payload::StartSection { func: _, range } => {
                tracing::trace!("Encountered Start section");
                tracing::error!("Expected WASM module with no Start section");
                miette::bail!("WASM module has Start section at {range:?}");
            }
            wasmparser::Payload::ElementSection(section) => {
                tracing::trace!("Encountered Element section");
                for element in section.into_iter_with_offsets() {
                    let (_el_idx, element) = element.into_diagnostic()?;
                    program.elements.push(element);
                }
            }
            wasmparser::Payload::DataCountSection { count: _, range: _ } => {
                tracing::trace!("Encountered DataCount section");
            }
            wasmparser::Payload::DataSection(section) => {
                tracing::trace!("Encountered Data section");
                for segment in section.into_iter_with_offsets() {
                    program.data_segments.push(segment.into_diagnostic()?.1);
                }
            }
            wasmparser::Payload::CodeSectionStart {
                count: _,
                range: _,
                size: _,
            } => {
                tracing::trace!("Encountered CodeSectionStart");
            }
            wasmparser::Payload::CodeSectionEntry(func) => {
                tracing::trace!("Encountered CodeSectionEntry");
                program.func_bodies.push(func);
            }
            wasmparser::Payload::CustomSection(section) => {
                // Currently supported Custom sections:
                //  - DWARF sections (.debug_*)
                //  - NAME section (name)
                tracing::trace!("Encountered Custom section");
                if section.name().starts_with(".debug_") {
                    tracing::trace!("Encountered DWARF section");
                    program
                        .dwarf_sections
                        .push((section.name(), section.data()));
                } else if section.name() == "name" {
                    match section.as_known() {
                        KnownCustom::Name(subsections) => {
                            for subsection in subsections {
                                match subsection.into_diagnostic()? {
                                    wasmparser::Name::Function(naming) => {
                                        for naming in naming.into_iter_with_offsets() {
                                            let (_naming_index, naming) =
                                                naming.into_diagnostic()?;
                                            program.func_names.insert(naming.index, naming.name);
                                        }
                                    }
                                    wasmparser::Name::Unknown { ty, data: _, range } => {
                                        tracing::warn!(
                                            "Encountered Name subsection with unknown kind {ty} at {range:?}"
                                        );
                                    }
                                    _ => { /* ignore everything else */ }
                                }
                            }
                        }
                        _ => (),
                    }
                } else {
                    tracing::warn!(
                        "Encountered unrecognized Custom section `{}`",
                        section.name()
                    );
                    // miette::bail!("Unknown Custom section `{}`", section.name());
                }
            }
            wasmparser::Payload::UnknownSection {
                id,
                contents: _,
                range: _,
            } => {
                tracing::error!("Encountered unknown section");
                miette::bail!("Unknown section type: 0x{id:02x}");
            }
            wasmparser::Payload::End(end_offset) => {
                tracing::trace!("Reached module end at offset {end_offset}");
            }
            x => {
                tracing::error!("Encountered unknown payload");
                miette::bail!("Encountered unexpected payload: {x:?}");
            }
        }
    }
    Ok(Program::from_program_data(program))
}
