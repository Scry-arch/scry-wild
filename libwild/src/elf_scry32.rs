//! Support for linking 32-bit Scry ELF objects.
//!
//! Scry programs are static executables loaded at address 0. There is no dynamic linking, no PLT
//! and no TLS.

use crate::bail;
use crate::elf::Elf32;
use crate::error;
use crate::error::Result;
use crate::platform::Platform;
use crate::platform::PreviousRelocationInfo;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::scry32::EM_SCRY;
use linker_utils::scry32::RelaxationKind;
use linker_utils::scry32::rel_type_to_string;

pub(crate) struct ElfScry32;

impl crate::platform::Arch for ElfScry32 {
    type Relaxation = Relaxation;
    type Platform = Elf32;

    /// scryer starts executing at address 0, so that's where static executables go.
    const DEFAULT_LOAD_ADDRESS: u64 = 0;

    fn arch_identifier() -> <Self::Platform as Platform>::ArchIdentifier {
        EM_SCRY
    }

    #[inline(always)]
    fn relocation_from_raw(r_type: object::elf::RelocationType) -> Result<RelocationKindInfo> {
        linker_utils::scry32::relocation_type_from_raw(r_type).ok_or_else(|| {
            error!(
                "Unsupported relocation type {}",
                Self::rel_type_to_string(r_type)
            )
        })
    }

    fn get_dynamic_relocation_type(
        relocation: DynamicRelocationKind,
    ) -> object::elf::RelocationType {
        // Scry executables are always static, so the linker should never need one of these.
        unreachable!("Scry has no dynamic relocations, but the linker tried to emit {relocation:?}")
    }

    fn rel_type_to_string(r_type: object::elf::RelocationType) -> std::borrow::Cow<'static, str> {
        rel_type_to_string(r_type)
    }

    fn write_plt_entry(
        _plt_entry: &mut [u8],
        _got_address: u64,
        _plt_address: u64,
    ) -> crate::error::Result {
        bail!("Scry has no PLT");
    }

    fn tp_offset_start(layout: &crate::layout::Layout<Elf32>) -> u64 {
        layout.tls_start_address()
    }

    /// Scry is single-threaded and has no TLS, so there is no DTV.
    fn get_dtv_offset() -> u64 {
        0
    }

    fn get_property_class(_property_type: u32) -> Option<crate::elf::PropertyClass> {
        None
    }

    fn merge_eflags(
        eflags: impl Iterator<Item = object::elf::FileFlags>,
    ) -> Result<object::elf::FileFlags> {
        Ok(eflags.fold(object::elf::FileFlags(0), |merged, flags| merged | flags))
    }

    fn high_part_relocations() -> &'static [object::elf::RelocationType] {
        &[]
    }

    #[allow(unused_variables)]
    #[inline(always)]
    fn new_relaxation(
        relocation_kind: object::elf::RelocationType,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: crate::value_flags::ValueFlags,
        output_kind: crate::output_kind::OutputKind,
        section_flags: linker_utils::elf::SectionFlags,
        relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
        _sym_addr: u64,
        _section_address: u64,
        _rel_addend: i64,
        _previous_relocation: Option<PreviousRelocationInfo<object::elf::RelocationType>>,
    ) -> Option<Self::Relaxation>
    where
        Self: std::marker::Sized,
    {
        None
    }

    fn get_source_info<'data>(
        object: &<Self::Platform as Platform>::File<'data>,
        relocations: &<Self::Platform as Platform>::RelocationSections,
        section: &<Self::Platform as Platform>::SectionHeader,
        offset_in_section: u64,
    ) -> Result<crate::platform::SourceInfo> {
        crate::dwarf_address_info::get_source_info::<crate::elf::Class32, Self>(
            object,
            relocations,
            section,
            offset_in_section,
        )
    }
}

// Scry has no relaxations, so `new_relaxation` always returns `None` and this type is never
// constructed.
#[derive(Debug, Clone)]
pub(crate) struct Relaxation {
    kind: RelaxationKind,
    rel_info: RelocationKindInfo,
    mandatory: bool,
}

impl crate::platform::Relaxation for Relaxation {
    fn apply(&self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut i64) {
        self.kind.apply(section_bytes, offset_in_section, addend);
    }

    fn rel_info(&self) -> RelocationKindInfo {
        self.rel_info
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        &self.kind
    }

    fn next_modifier(&self) -> RelocationModifier {
        self.kind.next_modifier()
    }

    fn is_mandatory(&self) -> bool {
        self.mandatory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Architecture;
    use crate::args::RelocationModel;
    use crate::args::elf::ElfArgs;
    use crate::elf::Class32;
    use crate::elf::File;
    use crate::output_kind::OutputKind;
    use crate::platform::Arch;
    use crate::platform::Args as _;
    use crate::platform::ObjectFile as _;
    use linker_utils::scry32::EM_SCRY;
    use object::Object as _;
    use object::ObjectSection as _;
    use object::ObjectSymbol as _;
    use object::elf::RelocationType;
    use object::read::elf::FileHeader as _;
    use object::read::elf::ProgramHeader as _;

    /// Builds a relocatable ELF32 Scry object with a single `_start` function in `.text`. The
    /// object crate doesn't know about Scry, so we write an x32 object (ELF32 with an x86-64
    /// machine number) and then patch in the Scry machine number.
    fn scry32_object() -> Vec<u8> {
        let mut object = object::write::Object::new(
            object::BinaryFormat::Elf,
            object::Architecture::X86_64_X32,
            object::Endianness::Little,
        );
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        let offset = object.append_section_data(text, &[0; 8], 4);
        object.add_symbol(object::write::Symbol {
            name: b"_start".to_vec(),
            value: offset,
            size: 8,
            kind: object::SymbolKind::Text,
            scope: object::SymbolScope::Linkage,
            weak: false,
            section: object::write::SymbolSection::Section(text),
            flags: object::SymbolFlags::None,
        });
        let mut bytes = object.write().unwrap();

        // e_machine lives at the same offset in ELF32 and ELF64 headers.
        const E_MACHINE_OFFSET: usize = 18;
        bytes[E_MACHINE_OFFSET..E_MACHINE_OFFSET + 2].copy_from_slice(&EM_SCRY.0.to_le_bytes());

        bytes
    }

    #[test]
    fn arch_identifier_is_scry() {
        assert_eq!(ElfScry32::arch_identifier(), EM_SCRY);
    }

    #[test]
    fn programs_are_placed_at_address_zero() {
        // scryer starts executing at address 0, so that's where a static executable must go.
        assert_eq!(ElfScry32::DEFAULT_LOAD_ADDRESS, 0);
        assert_eq!(
            ElfScry32::start_memory_address(OutputKind::StaticExecutable(RelocationModel::Fixed)),
            0
        );
    }

    #[test]
    fn unknown_relocations_are_reported_by_name() {
        let err = ElfScry32::relocation_from_raw(RelocationType(200)).unwrap_err();
        assert!(
            format!("{err:?}").contains("Unknown scry32 relocation type 0xc8"),
            "{err:?}"
        );
        assert_eq!(
            ElfScry32::rel_type_to_string(RelocationType(3)),
            "R_SCRY_ABS32"
        );
    }

    #[test]
    fn parses_scry32_object() {
        let bytes = scry32_object();
        let file = File::<Class32>::parse_bytes(&bytes, false).unwrap();
        assert_eq!(file.arch, Some(Architecture::Scry32));
        assert!(file.section_by_name(".text").is_some());
    }

    #[test]
    fn links_static_executable() {
        let dir = tempfile::tempdir().unwrap();
        let input_path = dir.path().join("start.o");
        let output_path = dir.path().join("out");
        std::fs::write(&input_path, scry32_object()).unwrap();

        let mut elf_args = ElfArgs::new().unwrap();
        elf_args
            .parse(
                [
                    "-m",
                    "elf32scry",
                    "-z",
                    "noexecstack",
                    "-o",
                    output_path.to_str().unwrap(),
                    input_path.to_str().unwrap(),
                ]
                .into_iter(),
            )
            .unwrap();
        let args = crate::args::Args::Elf(elf_args);

        let linker = crate::Linker::new();
        let output = linker.run(&args).unwrap();
        drop(output);
        drop(linker);

        let bytes = std::fs::read(&output_path).unwrap();

        assert_eq!(bytes[crate::elf::EI_CLASS], object::elf::ELFCLASS32.0);
        let file = object::read::elf::ElfFile32::<object::LittleEndian>::parse(&*bytes).unwrap();
        let header = file.elf_header();
        assert_eq!(header.e_machine(object::LittleEndian), EM_SCRY);
        assert_eq!(header.e_type(object::LittleEndian), object::elf::ET_EXEC);

        // The executable is placed at address 0 and the entry point is `_start`.
        let first_load = file
            .elf_program_headers()
            .iter()
            .find(|p| p.p_type(object::LittleEndian) == object::elf::PT_LOAD)
            .unwrap();
        assert_eq!(first_load.p_vaddr(object::LittleEndian), 0);

        let start = file.symbols().find(|s| s.name() == Ok("_start")).unwrap();
        assert_eq!(
            u64::from(header.e_entry(object::LittleEndian)),
            start.address()
        );

        let text = file.section_by_name(".text").unwrap();
        assert!(text.address() <= start.address());
        assert!(start.address() + 8 <= text.address() + text.size());

        // Nothing in a static Scry executable should require a dynamic loader.
        assert!(file.section_by_name(".dynamic").is_none());
    }

    /// A `const` instruction (type field set) followed by three `grow` instructions, with the
    /// immediates zeroed. This is what the compiler emits at the site of an `R_SCRY_ABS32`.
    const CHAIN: [u8; 8] = [0x90, 0, 0xc0, 0, 0xc0, 0, 0xc0, 0];

    /// The chain with `address` filled in, most significant byte first.
    fn chain_for(address: u32) -> [u8; 8] {
        let [b0, b1, b2, b3] = address.to_be_bytes();
        [0x90, b0, 0xc0, b1, 0xc0, b2, 0xc0, b3]
    }

    /// Builds a relocatable ELF32 Scry object using the supplied function to populate it.
    fn scry32_object_with(build: impl FnOnce(&mut object::write::Object)) -> Vec<u8> {
        elf32_object_with(EM_SCRY, build)
    }

    /// Builds a relocatable ELF32 object tagged with `machine`, using the supplied function to
    /// populate it. The object crate writes an x32 object (ELF32 with an x86-64 machine number),
    /// after which the machine number is patched.
    fn elf32_object_with(
        machine: object::elf::Machine,
        build: impl FnOnce(&mut object::write::Object),
    ) -> Vec<u8> {
        let mut object = object::write::Object::new(
            object::BinaryFormat::Elf,
            object::Architecture::X86_64_X32,
            object::Endianness::Little,
        );
        build(&mut object);
        let mut bytes = object.write().unwrap();

        const E_MACHINE_OFFSET: usize = 18;
        bytes[E_MACHINE_OFFSET..E_MACHINE_OFFSET + 2].copy_from_slice(&machine.0.to_le_bytes());

        bytes
    }

    fn global_symbol(
        name: &str,
        section: object::write::SectionId,
        value: u64,
        size: u64,
        kind: object::SymbolKind,
    ) -> object::write::Symbol {
        object::write::Symbol {
            name: name.as_bytes().to_vec(),
            value,
            size,
            kind,
            scope: object::SymbolScope::Dynamic,
            weak: false,
            section: object::write::SymbolSection::Section(section),
            flags: object::SymbolFlags::None,
        }
    }

    fn undefined_symbol(name: &str) -> object::write::Symbol {
        object::write::Symbol {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: object::SymbolKind::Unknown,
            scope: object::SymbolScope::Dynamic,
            weak: false,
            section: object::write::SymbolSection::Undefined,
            flags: object::SymbolFlags::None,
        }
    }

    fn relocation(
        offset: u64,
        symbol: object::write::SymbolId,
        addend: i64,
        r_type: RelocationType,
    ) -> object::write::Relocation {
        object::write::Relocation {
            offset,
            symbol,
            addend,
            flags: object::RelocationFlags::Elf { r_type },
        }
    }

    /// Links the supplied objects into a static executable and returns its bytes.
    fn link(objects: &[Vec<u8>], extra_args: &[&str]) -> crate::error::Result<Vec<u8>> {
        let dir = tempfile::tempdir().unwrap();
        let output_path = dir.path().join("out");
        let input_paths = objects
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                let path = dir.path().join(format!("{i}.o"));
                std::fs::write(&path, bytes).unwrap();
                path
            })
            .collect::<Vec<_>>();

        let mut args = vec!["-m", "elf32scry", "-z", "noexecstack"];
        args.extend_from_slice(extra_args);
        args.extend(["-o", output_path.to_str().unwrap()]);
        args.extend(input_paths.iter().map(|p| p.to_str().unwrap()));

        let mut elf_args = ElfArgs::new().unwrap();
        elf_args.parse(args.into_iter()).unwrap();
        let args = crate::args::Args::Elf(elf_args);

        let linker = crate::Linker::new();
        let output = linker.run(&args)?;
        drop(output);
        drop(linker);

        Ok(std::fs::read(&output_path).unwrap())
    }

    /// An object whose `_start` materialises `helper` and `helper + 4` in two chains.
    fn caller_object() -> Vec<u8> {
        scry32_object_with(|object| {
            let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
            let mut code = CHAIN.to_vec();
            code.extend_from_slice(&CHAIN);
            object.append_section_data(text, &code, 2);
            object.add_symbol(global_symbol(
                "_start",
                text,
                0,
                16,
                object::SymbolKind::Text,
            ));
            let helper = object.add_symbol(undefined_symbol("helper"));
            object
                .add_relocation(
                    text,
                    relocation(0, helper, 0, linker_utils::scry32::R_SCRY_ABS32),
                )
                .unwrap();
            object
                .add_relocation(
                    text,
                    relocation(8, helper, 4, linker_utils::scry32::R_SCRY_ABS32),
                )
                .unwrap();
        })
    }

    /// An object defining `helper` and `unused`, each in its own section.
    fn callee_object() -> Vec<u8> {
        scry32_object_with(|object| {
            let helper_section = object.add_section(
                Vec::new(),
                b".text.helper".to_vec(),
                object::SectionKind::Text,
            );
            object.append_section_data(helper_section, &[0x01, 0x00, 0x01, 0x00], 2);
            object.add_symbol(global_symbol(
                "helper",
                helper_section,
                0,
                4,
                object::SymbolKind::Text,
            ));

            let unused_section = object.add_section(
                Vec::new(),
                b".text.unused".to_vec(),
                object::SectionKind::Text,
            );
            object.append_section_data(unused_section, &[0x01, 0x00], 2);
            object.add_symbol(global_symbol(
                "unused",
                unused_section,
                0,
                2,
                object::SymbolKind::Text,
            ));
        })
    }

    fn parse_output(bytes: &[u8]) -> object::read::elf::ElfFile32<'_, object::LittleEndian> {
        object::read::elf::ElfFile32::<object::LittleEndian>::parse(bytes).unwrap()
    }

    /// Returns `len` bytes of the output starting at `symbol`.
    fn bytes_at<'a>(
        file: &'a object::read::elf::ElfFile32<'_, object::LittleEndian>,
        symbol: &str,
        len: usize,
    ) -> &'a [u8] {
        let symbol = file.symbol_by_name(symbol).unwrap();
        let section = file
            .section_by_index(symbol.section_index().unwrap())
            .unwrap();
        let offset = (symbol.address() - section.address()) as usize;
        &section.data().unwrap()[offset..offset + len]
    }

    #[test]
    fn abs32_relocations_materialise_symbol_addresses() {
        let bytes = link(&[caller_object(), callee_object()], &[]).unwrap();
        let file = parse_output(&bytes);

        let helper = u32::try_from(file.symbol_by_name("helper").unwrap().address()).unwrap();
        assert_ne!(helper, 0);

        let mut expected = chain_for(helper).to_vec();
        expected.extend_from_slice(&chain_for(helper + 4));
        assert_eq!(bytes_at(&file, "_start", 16), &expected[..]);
    }

    #[test]
    fn r_scry_32_relocations_write_pointers_in_data() {
        let data_object = scry32_object_with(|object| {
            let data = object.add_section(Vec::new(), b".data".to_vec(), object::SectionKind::Data);
            object.append_section_data(data, &[0; 8], 4);
            let table =
                object.add_symbol(global_symbol("table", data, 0, 8, object::SymbolKind::Data));
            let helper = object.add_symbol(undefined_symbol("helper"));

            // `_start` materialises the address of `table`, which keeps `.data` alive: wild
            // garbage-collects unreferenced sections by default.
            let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
            object.append_section_data(text, &CHAIN, 2);
            object.add_symbol(global_symbol(
                "_start",
                text,
                0,
                8,
                object::SymbolKind::Text,
            ));
            object
                .add_relocation(
                    text,
                    relocation(0, table, 0, linker_utils::scry32::R_SCRY_ABS32),
                )
                .unwrap();

            object
                .add_relocation(
                    data,
                    relocation(0, helper, 0, linker_utils::scry32::R_SCRY_32),
                )
                .unwrap();
            object
                .add_relocation(
                    data,
                    relocation(4, helper, -2, linker_utils::scry32::R_SCRY_32),
                )
                .unwrap();
        });

        let bytes = link(&[data_object, callee_object()], &[]).unwrap();
        let file = parse_output(&bytes);

        let helper = u32::try_from(file.symbol_by_name("helper").unwrap().address()).unwrap();
        let mut expected = helper.to_le_bytes().to_vec();
        expected.extend_from_slice(&(helper - 2).to_le_bytes());
        assert_eq!(bytes_at(&file, "table", 8), &expected[..]);
    }

    #[test]
    fn gc_sections_keeps_functions_reached_through_abs32() {
        let bytes = link(&[caller_object(), callee_object()], &["--gc-sections"]).unwrap();
        let file = parse_output(&bytes);

        let helper = file
            .symbol_by_name("helper")
            .expect("helper is referenced from _start");
        assert!(
            file.symbol_by_name("unused").is_none(),
            "unused should be discarded"
        );

        let helper = u32::try_from(helper.address()).unwrap();
        assert_eq!(bytes_at(&file, "_start", 8), &chain_for(helper));
    }

    #[test]
    fn unresolved_symbols_are_reported() {
        let err = link(&[caller_object()], &[]).unwrap_err();
        let message = format!("{err:?}");
        assert!(message.contains("helper"), "{message}");
    }

    /// A machine number that no architecture uses.
    const FOREIGN_MACHINE: object::elf::Machine = object::elf::Machine(0xfeed);

    /// Builds an archive from the supplied `(member name, contents)` pairs.
    fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = ar::Builder::new(Vec::new());
        for (name, contents) in members {
            let header = ar::Header::new(name.as_bytes().to_vec(), contents.len() as u64);
            builder.append(&header, *contents).unwrap();
        }
        builder.into_inner().unwrap()
    }

    /// rustc writes a few objects itself, tagged with whatever machine number it associates with
    /// the target rather than the one the code objects use. They contain no code, data or
    /// relocations, so the linker accepts them regardless of their machine number.
    #[test]
    fn links_with_architecture_neutral_inputs() {
        // Like rustc's `symbols.o`: only symbol references.
        let symbols_object = elf32_object_with(FOREIGN_MACHINE, |object| {
            object.add_symbol(undefined_symbol("_start"));
        });

        // Like the metadata members rustc puts in every rlib, alongside the real code object.
        let metadata_object = elf32_object_with(FOREIGN_MACHINE, |object| {
            let section = object.add_section(
                Vec::new(),
                b".rmeta".to_vec(),
                object::SectionKind::Metadata,
            );
            object.append_section_data(section, b"metadata", 1);
        });
        let rlib = archive(&[
            ("lib.rmeta", &metadata_object),
            ("helper.o", &callee_object()),
        ]);

        let dir = tempfile::tempdir().unwrap();
        let rlib_path = dir.path().join("libhelper.rlib");
        std::fs::write(&rlib_path, rlib).unwrap();

        let bytes = link(
            &[caller_object(), symbols_object],
            &[rlib_path.to_str().unwrap()],
        )
        .unwrap();
        let file = parse_output(&bytes);

        let helper = u32::try_from(file.symbol_by_name("helper").unwrap().address()).unwrap();
        assert_eq!(bytes_at(&file, "_start", 8), &chain_for(helper));
    }

    #[test]
    fn foreign_objects_with_code_are_rejected() {
        let foreign_code = elf32_object_with(FOREIGN_MACHINE, |object| {
            let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
            object.append_section_data(text, &[0; 4], 4);
        });

        let err = link(&[caller_object(), callee_object(), foreign_code], &[]).unwrap_err();
        let message = format!("{err:?}");
        assert!(message.contains("0xfeed"), "{message}");
    }
}
