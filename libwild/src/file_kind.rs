//! Code for identifying what sort of file we're dealing with based on the bytes of the file.

use crate::bail;
use crate::elf;
use crate::ensure;
use crate::error::Result;
use object::Endian;
use object::Endianness;
use object::LittleEndian;
use object::macho;
use object::read::elf::FileHeader;
use object::read::elf::SectionHeader;
use object::read::macho::MachHeader;
use zerocopy::IntoBytes;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum FileKind {
    ElfObject,
    ElfDynamic,
    MachOObject,
    MachODylib,
    FatMachOObject,
    MachOStubLibrary,
    WasmObject,
    Archive,
    ThinArchive,
    Text,
    LlvmIr,
    GccIr,
}

impl FileKind {
    pub(crate) fn identify_bytes(bytes: &[u8]) -> Result<FileKind> {
        if bytes.starts_with(&object::archive::MAGIC) {
            Ok(FileKind::Archive)
        } else if bytes.starts_with(&object::archive::THIN_MAGIC) {
            Ok(FileKind::ThinArchive)
        } else if bytes.starts_with(&object::elf::ELFMAG) {
            if bytes.len() < elf::EI_NIDENT {
                bail!("Invalid ELF file");
            }
            ensure!(
                object::elf::DataEncoding(bytes[elf::EI_DATA]) == object::elf::ELFDATA2LSB,
                "Only little endian is currently supported"
            );

            match object::elf::FileClass(bytes[elf::EI_CLASS]) {
                object::elf::ELFCLASS32 => identify_elf::<elf::FileHeader32>(bytes),
                object::elf::ELFCLASS64 => identify_elf::<elf::FileHeader64>(bytes),
                class => bail!("Unsupported ELF class {}", class.0),
            }
        } else if bytes.starts_with(macho::MH_MAGIC_64.as_bytes())
            || bytes.starts_with(&macho::MH_MAGIC_64.to_be_bytes())
        {
            determine_macho_kind(bytes)
        } else if bytes.starts_with(b"\0asm") {
            // Wasm binary magic number is `\0asm` followed by a 4-byte version.
            ensure!(bytes.len() >= 8, "Invalid Wasm file (too short)");
            Ok(FileKind::WasmObject)
        } else if bytes.starts_with(&macho::FAT_MAGIC.to_be_bytes())
            || bytes.starts_with(&macho::FAT_MAGIC_64.to_be_bytes())
        {
            Ok(FileKind::FatMachOObject)
        } else if bytes.starts_with(b"--- !tapi-tbd") || bytes.starts_with(b"tbd-version:") {
            Ok(FileKind::MachOStubLibrary)
        } else if bytes.is_ascii() {
            Ok(FileKind::Text)
        } else if bytes.starts_with(b"BC") {
            Ok(FileKind::LlvmIr)
        } else if let Some(start) = bytes.get(..4) {
            bail!("Couldn't identify file type starting with {start:x?}");
        } else {
            bail!("Input file is only {} bytes", bytes.len());
        }
    }

    pub(crate) fn is_compiler_ir(self) -> bool {
        matches!(self, FileKind::LlvmIr | FileKind::GccIr)
    }
}

fn identify_elf<H: FileHeader<Endian = LittleEndian>>(bytes: &[u8]) -> Result<FileKind> {
    let header = H::parse(bytes).map_err(|_| crate::error!("Invalid ELF file"))?;

    match header.e_type(LittleEndian) {
        object::elf::ET_REL => {
            if is_gcc_bitcode(bytes, header).unwrap_or(false) {
                Ok(FileKind::GccIr)
            } else if is_llvm_bitcode(bytes, header).unwrap_or(false) {
                Ok(FileKind::LlvmIr)
            } else {
                Ok(FileKind::ElfObject)
            }
        }
        object::elf::ET_DYN => Ok(FileKind::ElfDynamic),
        t => bail!("Unsupported ELF kind {t}"),
    }
}

fn determine_macho_kind(bytes: &[u8]) -> Result<FileKind> {
    let header = macho::MachHeader64::<object::Endianness>::parse(bytes, 0)?;

    ensure!(
        header.endian()?.is_little_endian(),
        "Only little endian is currently supported"
    );

    ensure!(
        header.cputype(Endianness::Little) == macho::CPU_TYPE_ARM64,
        "Only ARM64 is currently supported"
    );

    match header.filetype(Endianness::Little) {
        macho::MH_OBJECT => Ok(FileKind::MachOObject),
        macho::MH_DYLIB => Ok(FileKind::MachODylib),
        other => bail!("Unsupported MachO input file type {other:?}"),
    }
}

/// Returns whether the supplied file contents is GCC IR. Scanning the entire section table would be
/// expensive. Instead, we assume that we'll find a GCC LTO section within the first few sections,
/// so just scan part of the section header strings table. It's unfortunate that GCC didn't tag
/// these objects in some fast-to-check way.
fn is_gcc_bitcode<H: FileHeader<Endian = LittleEndian>>(data: &[u8], header: &H) -> Option<bool> {
    // If we don't have plugin support, then we skip checking if the file contains GCC IR. If it is,
    // then we'll figure that out later on and report an error. We do this because this code has a
    // measurable performance impact.
    if !cfg!(all(feature = "plugins", unix)) {
        return Some(false);
    }
    let e = LittleEndian;
    let section_headers = header.section_headers(e, data).ok()?;
    let sh_str_index = header.shstrndx(e, data).ok()?;
    let strings_section_header = section_headers.get(sh_str_index as usize)?;
    let start_offset: u64 = strings_section_header.sh_offset(e).into();
    let start_offset = start_offset as usize;
    let len: u64 = strings_section_header.sh_size(e).into();
    let len = len as usize;
    // In observed GCC IR files, the LTO section names start at offset 44 and end at 454. We want to
    // scan roughly the middle of this range.
    const START: usize = 100;
    // The longest GCC LTO section name is 47 bytes. We scan a bit more in case the first LTO
    // section started later than START.
    const MAX_SCAN: usize = 200;
    let strings = data.get(start_offset + START..start_offset + (START + MAX_SCAN).min(len))?;
    Some(memchr::memmem::find(strings, b"\0.gnu.lto_.").is_some())
}

// TODO: Use object crate once a new version is up.
const SHT_LLVM_LTO: object::elf::SectionType = object::elf::SectionType(0x6fff4c0c);

fn is_llvm_bitcode<H: FileHeader<Endian = LittleEndian>>(data: &[u8], header: &H) -> Option<bool> {
    // If we don't have plugin support, then we skip checking if the file contains LLVM IR. If it
    // is, then we'll figure that out later on and report an error. We do this because this code
    // has a measurable performance impact.
    if !cfg!(all(feature = "plugins", unix)) {
        return Some(false);
    }
    let e = LittleEndian;
    let section_headers = header.section_headers(e, data).ok()?;
    Some(section_headers.iter().any(|s| s.sh_type(e) == SHT_LLVM_LTO))
}

impl std::fmt::Display for FileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FileKind::ElfObject => "ELF object",
            FileKind::ElfDynamic => "ELF dynamic",
            FileKind::MachOObject => "Mach-O object",
            FileKind::MachODylib => "Mach-O dylib",
            FileKind::WasmObject => "Wasm object",
            FileKind::FatMachOObject => "Fat Mach-O object",
            FileKind::MachOStubLibrary => "Mach-O TBD library",
            FileKind::Archive => "archive",
            FileKind::ThinArchive => "thin archive",
            FileKind::Text => "text",
            FileKind::LlvmIr => "LLVM-IR",
            FileKind::GccIr => "GCC-IR",
        };
        std::fmt::Display::fmt(s, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::Architecture;

    fn elf_object(arch: Architecture) -> Vec<u8> {
        let mut object =
            object::write::Object::new(object::BinaryFormat::Elf, arch, object::Endianness::Little);
        let text = object.add_section(Vec::new(), b".text".to_vec(), object::SectionKind::Text);
        object.append_section_data(text, &[0; 4], 4);
        object.write().unwrap()
    }

    #[test]
    fn identifies_elf64_object() {
        let bytes = elf_object(Architecture::X86_64);
        assert_eq!(bytes[elf::EI_CLASS], object::elf::ELFCLASS64.0);
        assert_eq!(
            FileKind::identify_bytes(&bytes).unwrap(),
            FileKind::ElfObject
        );
    }

    #[test]
    fn identifies_elf32_object() {
        // The x32 ABI produces ELF32 files with an x86-64 machine type.
        let bytes = elf_object(Architecture::X86_64_X32);
        assert_eq!(bytes[elf::EI_CLASS], object::elf::ELFCLASS32.0);
        assert_eq!(
            FileKind::identify_bytes(&bytes).unwrap(),
            FileKind::ElfObject
        );
    }

    #[test]
    fn rejects_unsupported_elf() {
        let bytes = elf_object(Architecture::X86_64_X32);

        let err = FileKind::identify_bytes(&bytes[..8]).unwrap_err();
        assert!(format!("{err:?}").contains("Invalid ELF file"), "{err:?}");

        let mut big_endian = bytes.clone();
        big_endian[elf::EI_DATA] = object::elf::ELFDATA2MSB.0;
        let err = FileKind::identify_bytes(&big_endian).unwrap_err();
        assert!(format!("{err:?}").contains("little endian"), "{err:?}");

        let mut bad_class = bytes;
        bad_class[elf::EI_CLASS] = 3;
        let err = FileKind::identify_bytes(&bad_class).unwrap_err();
        assert!(
            format!("{err:?}").contains("Unsupported ELF class 3"),
            "{err:?}"
        );
    }
}
