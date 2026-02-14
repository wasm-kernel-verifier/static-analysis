//! Parse WASM programs.

use miette::IntoDiagnostic;
use wasmparser::{
    Data, Element, Encoding, Export, FuncType, FunctionBody, Global, Import, MemoryType, Parser,
    Table, TagType,
};

/// Static representation of a WASM program, with all the information we need to run symbolic
/// interpretation.
pub struct Program<'a> {
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
}

#[tracing::instrument(skip(program))]
pub fn parse_wasm<'a>(program: &'a [u8], name: &'a str) -> miette::Result<Program<'a>> {
    let parser = Parser::new(0);

    let mut dwarf_sections: Vec<(&str, &[u8])> = vec![];
    let mut data_segments: Vec<Data> = vec![];
    let mut func_types: Vec<u32> = vec![];
    let mut func_bodies: Vec<FunctionBody> = vec![];
    let mut globals: Vec<Global> = vec![];
    let mut exports: Vec<Export> = vec![];
    let mut elements: Vec<Element> = vec![];
    let mut tags: Vec<TagType> = vec![];
    let mut memories: Vec<MemoryType> = vec![];
    let mut tables: Vec<Table> = vec![];
    let mut imports: Vec<Import> = vec![];
    let mut types: Vec<FuncType> = vec![];

    for payload in parser.parse_all(program) {
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
                    types.push(func_ty);
                }
            }
            wasmparser::Payload::ImportSection(section) => {
                tracing::trace!("Encountered Import section");
                for import in section.into_imports() {
                    imports.push(import.into_diagnostic()?);
                }
            }
            wasmparser::Payload::FunctionSection(section) => {
                tracing::trace!("Encountered Function section");
                for func_ty in section.into_iter_with_offsets() {
                    let (_func_ty_idx, func_ty) = func_ty.into_diagnostic()?;
                    func_types.push(func_ty);
                }
            }
            wasmparser::Payload::TableSection(section) => {
                tracing::trace!("Encountered Table section");
                for table in section.into_iter_with_offsets() {
                    let (_tbl_idx, table) = table.into_diagnostic()?;
                    tables.push(table);
                }
            }
            wasmparser::Payload::MemorySection(section) => {
                tracing::trace!("Encountered Memory section");
                for memory in section.into_iter_with_offsets() {
                    let (_mem_idx, memory) = memory.into_diagnostic()?;
                    memories.push(memory);
                }
            }
            wasmparser::Payload::TagSection(section) => {
                tracing::trace!("Encountered Tag section");
                for tag in section.into_iter_with_offsets() {
                    let (_tag_idx, tag) = tag.into_diagnostic()?;
                    tags.push(tag);
                }
            }
            wasmparser::Payload::GlobalSection(section) => {
                tracing::trace!("Encountered Global section");
                for global in section.into_iter_with_offsets() {
                    let (_gl_idx, global) = global.into_diagnostic()?;
                    globals.push(global);
                }
            }
            wasmparser::Payload::ExportSection(section) => {
                tracing::trace!("Encountered Export section");
                for export in section.into_iter_with_offsets() {
                    let (_ex_idx, export) = export.into_diagnostic()?;
                    exports.push(export);
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
                    elements.push(element);
                }
            }
            wasmparser::Payload::DataCountSection { count: _, range: _ } => {
                tracing::trace!("Encountered DataCount section");
            }
            wasmparser::Payload::DataSection(section) => {
                tracing::trace!("Encountered Data section");
                for segment in section.into_iter_with_offsets() {
                    data_segments.push(segment.into_diagnostic()?.1);
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
                func_bodies.push(func);
            }
            wasmparser::Payload::CustomSection(section) => {
                // Currently supported Custom sections:
                //  - DWARF sections (.debug_*)
                tracing::trace!("Encountered Custom section");
                if section.name().starts_with(".debug_") {
                    tracing::trace!("Encountered DWARF section");
                    dwarf_sections.push((section.name(), section.data()));
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
    Ok(Program {
        name,
        dwarf_sections,
        data_segments,
        func_types,
        func_bodies,
        globals,
        exports,
        elements,
        tags,
        memories,
        tables,
        imports,
        types,
    })
}
