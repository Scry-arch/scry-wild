use crate::bail;
use crate::error::Result;
use linker_utils::scry32::EM_SCRY;
use object::elf::EM_AARCH64;
use object::elf::EM_LOONGARCH;
use object::elf::EM_PPC64;
use object::elf::EM_RISCV;
use object::elf::EM_X86_64;
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Architecture {
    X86_64,
    AArch64,
    RiscV64,
    LoongArch64,
    Ppc64,
    Scry32,
    Unsupported,
}

impl TryFrom<object::elf::Machine> for Architecture {
    type Error = crate::error::Error;

    fn try_from(arch: object::elf::Machine) -> Result<Self, Self::Error> {
        match arch {
            EM_X86_64 => Ok(Self::X86_64),
            EM_AARCH64 => Ok(Self::AArch64),
            EM_RISCV => Ok(Self::RiscV64),
            EM_LOONGARCH => Ok(Self::LoongArch64),
            EM_PPC64 => Ok(Self::Ppc64),
            EM_SCRY => Ok(Self::Scry32),
            _ => bail!("Unsupported architecture: 0x{:x}", arch),
        }
    }
}

impl Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let arch = match self {
            Architecture::X86_64 => "x86_64",
            Architecture::AArch64 => "aarch64",
            Architecture::RiscV64 => "riscv64",
            Architecture::LoongArch64 => "loongarch64",
            Architecture::Ppc64 => "ppc64",
            Architecture::Scry32 => "scry32",
            Architecture::Unsupported => "unsupported",
        };
        write!(f, "{arch}")
    }
}

impl Architecture {
    pub(crate) fn parse_output_format(format: &[u8]) -> Self {
        if let Some(format) = format.strip_prefix(b"elf64-") {
            match format {
                b"x86-64" => Self::X86_64,
                b"aarch64" | b"littleaarch64" => Self::AArch64,
                b"littleriscv" => Self::RiscV64,
                b"loongarch" => Self::LoongArch64,
                b"powerpcle" => Self::Ppc64,
                _ => Self::Unsupported,
            }
        } else if let Some(format) = format.strip_prefix(b"elf32-") {
            match format {
                b"scry" => Self::Scry32,
                _ => Self::Unsupported,
            }
        } else {
            Self::Unsupported
        }
    }
}

pub(crate) const SUPPORTED_TARGETS: &str = "elf64-x86-64 elf64-littleaarch64 elf64-littleriscv \
     elf64-loongarch elf64-powerpcle elf32-scry";

#[cfg(test)]
mod tests {
    use super::*;
    use linker_utils::scry32::EM_SCRY;

    #[test]
    fn scry32_is_recognised() {
        assert_eq!(
            Architecture::try_from(EM_SCRY).unwrap(),
            Architecture::Scry32
        );
        assert_eq!(
            Architecture::try_from(object::elf::Machine(264)).unwrap(),
            Architecture::Scry32
        );
        assert_eq!(Architecture::Scry32.to_string(), "scry32");
    }

    #[test]
    fn scry32_output_format() {
        assert_eq!(
            Architecture::parse_output_format(b"elf32-scry"),
            Architecture::Scry32
        );
        // Scry objects are ELF32, so the 64-bit spelling must not be accepted.
        assert_eq!(
            Architecture::parse_output_format(b"elf64-scry"),
            Architecture::Unsupported
        );
        assert!(SUPPORTED_TARGETS.split(' ').any(|t| t == "elf32-scry"));
        // Existing targets must keep parsing.
        assert_eq!(
            Architecture::parse_output_format(b"elf64-x86-64"),
            Architecture::X86_64
        );
    }
}
