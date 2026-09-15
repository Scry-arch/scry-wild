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
        assert_eq!(file.arch, Architecture::Scry32);
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
}
