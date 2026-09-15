//! Support for the Scry architecture.
//!
//! Scry is a 32-bit little-endian ISA. Its ELF objects use `EM_SCRY` and RELA relocations. The
//! constants are defined here rather than taken from the `object` crate, since upstream `object`
//! doesn't know about Scry.

use crate::elf::RelocationKindInfo;
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

/// Returns how to apply the supplied relocation type, or `None` if it isn't supported.
#[must_use]
pub const fn relocation_type_from_raw(_r_type: RelocationType) -> Option<RelocationKindInfo> {
    None
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
}
