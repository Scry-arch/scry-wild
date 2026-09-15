//! Support for the Scry architecture.
//!
//! Scry is a 32-bit little-endian ISA. Its ELF objects use `EM_SCRY` and RELA relocations. The
//! constants are defined here rather than taken from the `object` crate, since upstream `object`
//! doesn't know about Scry.

use crate::elf::AllowedRange;
use crate::elf::BitMask;
use crate::elf::RelocationInstruction;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use crate::elf::Scry32Instruction;
use crate::relaxation::RelocationModifier;
use object::elf::Machine;
use object::elf::RelocationType;
use std::borrow::Cow;

/// The `e_machine` value for Scry.
pub const EM_SCRY: Machine = Machine(264);

/// No relocation.
pub const R_SCRY_NONE: RelocationType = RelocationType(0);

/// A 32-bit absolute value, `S + A`, stored as a plain little-endian word. Used for pointers in
/// data.
pub const R_SCRY_32: RelocationType = RelocationType(1);

/// A 64-bit absolute value, `S + A`, stored as a plain little-endian word.
pub const R_SCRY_64: RelocationType = RelocationType(2);

/// A 32-bit absolute address, `S + A`, materialised in code by a `const` instruction followed by
/// three `grow` instructions. Each of the four 16-bit instruction words carries one byte of the
/// address in its high byte, most significant byte first.
pub const R_SCRY_ABS32: RelocationType = RelocationType(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaxationKind {
    /// Leave the instruction alone. Used when we only want to change the kind of relocation used.
    NoOp,
}

impl RelaxationKind {
    pub fn apply(self, _section_bytes: &mut [u8], _offset_in_section: &mut u64, _addend: &mut i64) {
        match self {
            RelaxationKind::NoOp => {}
        }
    }

    #[must_use]
    pub fn next_modifier(&self) -> RelocationModifier {
        RelocationModifier::Normal
    }
}

#[must_use]
pub fn rel_type_to_string(r_type: RelocationType) -> Cow<'static, str> {
    let name = match r_type {
        R_SCRY_NONE => "R_SCRY_NONE",
        R_SCRY_32 => "R_SCRY_32",
        R_SCRY_64 => "R_SCRY_64",
        R_SCRY_ABS32 => "R_SCRY_ABS32",
        _ => return Cow::Owned(format!("Unknown scry32 relocation type 0x{r_type:x}")),
    };
    Cow::Borrowed(name)
}

/// The range of a 32-bit absolute value. The negative lower bound admits a sign-extended negative
/// addend, not a negative address.
const RANGE_32: AllowedRange = AllowedRange::new(-(1 << 31), 1 << 32);

/// Returns how to apply the supplied relocation type, or `None` if it isn't supported.
///
/// `R_SCRY_64` is deliberately unsupported: it only appears in 64-bit Scry objects, which can't be
/// linked into a 32-bit executable.
#[must_use]
pub const fn relocation_type_from_raw(r_type: RelocationType) -> Option<RelocationKindInfo> {
    let (kind, size, range) = match r_type {
        R_SCRY_NONE => (
            RelocationKind::None,
            RelocationSize::ByteSize(0),
            AllowedRange::no_check(),
        ),
        R_SCRY_32 => (
            RelocationKind::Absolute,
            RelocationSize::ByteSize(4),
            RANGE_32,
        ),
        R_SCRY_ABS32 => (
            RelocationKind::Absolute,
            RelocationSize::BitMasking(BitMask::new(
                RelocationInstruction::Scry32(Scry32Instruction::ConstGrowChain),
                0,
                32,
            )),
            RANGE_32,
        ),
        _ => return None,
    };

    Some(RelocationKindInfo {
        kind,
        size,
        mask: None,
        range,
        // Values are addresses of data as well as code, and data can be byte-aligned.
        alignment: 1,
        bias: 0,
        thunkable: false,
    })
}

impl Scry32Instruction {
    /// Writes the low 32 bits of `extracted_value` into the chain, one byte per instruction word,
    /// most significant byte first. The low byte of each word holds the opcode and is preserved.
    pub fn write_to_value(self, extracted_value: u64, _negative: bool, dest: &mut [u8]) {
        match self {
            Scry32Instruction::ConstGrowChain => {
                let bytes = (extracted_value as u32).to_be_bytes();
                for (i, byte) in bytes.into_iter().enumerate() {
                    dest[2 * i + 1] = byte;
                }
            }
        }
    }

    #[must_use]
    pub fn read_value(self, bytes: &[u8]) -> (u64, bool) {
        match self {
            Scry32Instruction::ConstGrowChain => {
                let value = u32::from_be_bytes([bytes[1], bytes[3], bytes[5], bytes[7]]);
                (u64::from(value), false)
            }
        }
    }

    /// The number of bytes that the instruction sequence occupies.
    #[must_use]
    pub fn write_windows_size(self) -> usize {
        match self {
            Scry32Instruction::ConstGrowChain => 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::DynamicRelocationKind;
    use object::elf::Machine;
    use object::elf::RelocationType;

    #[test]
    fn constants_match_the_scry_elf_abi() {
        assert_eq!(EM_SCRY, Machine(264));
        assert_eq!(R_SCRY_NONE, RelocationType(0));
        assert_eq!(R_SCRY_32, RelocationType(1));
        assert_eq!(R_SCRY_64, RelocationType(2));
        assert_eq!(R_SCRY_ABS32, RelocationType(3));
    }

    #[test]
    fn relocation_type_names() {
        assert_eq!(rel_type_to_string(R_SCRY_NONE), "R_SCRY_NONE");
        assert_eq!(rel_type_to_string(R_SCRY_32), "R_SCRY_32");
        assert_eq!(rel_type_to_string(R_SCRY_64), "R_SCRY_64");
        assert_eq!(rel_type_to_string(R_SCRY_ABS32), "R_SCRY_ABS32");
        assert_eq!(
            rel_type_to_string(RelocationType(200)),
            "Unknown scry32 relocation type 0xc8"
        );
    }

    #[test]
    fn unknown_relocation_types_are_rejected() {
        assert!(relocation_type_from_raw(RelocationType(200)).is_none());
    }

    #[test]
    fn scry_has_no_dynamic_relocations() {
        for r_type in [R_SCRY_NONE, R_SCRY_32, R_SCRY_64, R_SCRY_ABS32] {
            assert!(DynamicRelocationKind::from_scry32_r_type(r_type).is_none());
        }
    }

    #[test]
    fn r_scry_none_does_nothing() {
        let info = relocation_type_from_raw(R_SCRY_NONE).unwrap();
        assert_eq!(info.kind, RelocationKind::None);
        assert_eq!(info.size, RelocationSize::ByteSize(0));

        let mut bytes = [7u8; 2];
        info.write_to_buffer(0x1234, &mut bytes).unwrap();
        assert_eq!(bytes, [7, 7]);
    }

    #[test]
    fn r_scry_32_is_a_plain_little_endian_word() {
        let info = relocation_type_from_raw(R_SCRY_32).unwrap();
        assert_eq!(info.kind, RelocationKind::Absolute);
        assert_eq!(info.size, RelocationSize::ByteSize(4));
        // Data can be byte-aligned, so the value has no alignment requirement.
        assert_eq!(info.alignment, 1);
        // A 32-bit field, allowing a negative addend to sign-extend.
        assert_eq!(info.range, AllowedRange::new(-(1 << 31), 1 << 32));
        assert!(!info.thunkable);

        let mut bytes = [0xffu8; 6];
        info.write_to_buffer(0x0102_0304, &mut bytes).unwrap();
        assert_eq!(bytes, [0x04, 0x03, 0x02, 0x01, 0xff, 0xff]);
    }

    #[test]
    fn r_scry_64_is_not_supported_in_32_bit_links() {
        assert!(relocation_type_from_raw(R_SCRY_64).is_none());
    }

    #[test]
    fn r_scry_abs32_kind_info() {
        let info = relocation_type_from_raw(R_SCRY_ABS32).unwrap();
        assert_eq!(info.kind, RelocationKind::Absolute);
        assert_eq!(
            info.size,
            RelocationSize::BitMasking(BitMask::new(
                RelocationInstruction::Scry32(Scry32Instruction::ConstGrowChain),
                0,
                32
            ))
        );
        assert_eq!(info.alignment, 1);
        assert_eq!(info.range, AllowedRange::new(-(1 << 31), 1 << 32));
        assert!(!info.thunkable);
    }

    #[test]
    fn abs32_scatters_the_address_over_the_const_grow_chain() {
        let info = relocation_type_from_raw(R_SCRY_ABS32).unwrap();

        // A `const` (with a non-zero type field) followed by three `grow` instructions, with
        // garbage in the immediates, followed by an unrelated instruction that must be left alone.
        let mut bytes = [0x90, 0xaa, 0xc0, 0xbb, 0xc0, 0xcc, 0xc0, 0xdd, 0x12, 0x34];
        info.write_to_buffer(0x0102_0304, &mut bytes).unwrap();
        assert_eq!(
            bytes,
            [0x90, 0x01, 0xc0, 0x02, 0xc0, 0x03, 0xc0, 0x04, 0x12, 0x34]
        );
    }

    #[test]
    fn abs32_rejects_values_that_do_not_fit() {
        let info = relocation_type_from_raw(R_SCRY_ABS32).unwrap();
        let mut bytes = [0u8; 8];
        assert!(info.write_to_buffer(1 << 32, &mut bytes).is_err());
    }

    #[test]
    fn abs32_round_trips_through_read_value() {
        let instruction = Scry32Instruction::ConstGrowChain;
        let mut bytes = [0x90, 0, 0xc0, 0, 0xc0, 0, 0xc0, 0];
        instruction.write_to_value(0xdead_beef, false, &mut bytes);
        assert_eq!(bytes, [0x90, 0xde, 0xc0, 0xad, 0xc0, 0xbe, 0xc0, 0xef]);
        assert_eq!(instruction.read_value(&bytes), (0xdead_beef, false));

        // The chain is four 16-bit instructions.
        assert_eq!(
            RelocationInstruction::Scry32(instruction).write_windows_size(),
            8
        );
    }
}
