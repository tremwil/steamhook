use iced_x86::{OpKind, OpAccess, Register};

pub trait IsImmediate {
    /// Checks if the operand is any immediate.
    fn is_immediate(&self) -> bool;
}
impl IsImmediate for OpKind {
    #[inline]
    fn is_immediate(&self) -> bool {
        match *self {
            Self::Immediate8 | Self::Immediate16 | Self::Immediate32 | Self::Immediate64
            | Self::Immediate8to16 | Self::Immediate8to32 | Self::Immediate8to64 | Self::Immediate32to64 => true,
            _ => false
        }
    }
}

pub trait CanWrite {
    /// Checks if the value *may* be written to memory/registers. 
    fn can_write(&self) -> bool;
}
impl CanWrite for OpAccess {
    #[inline]
    fn can_write(&self) -> bool {
        match *self {
            Self::CondWrite | Self::ReadCondWrite | Self::ReadWrite | Self::Write => true,
            _ => false 
        }
    }
}

pub trait IsVolatile {
    /// Checks if the register is a **full width** volatile register according to the MSVC calling convention.
    fn is_volatile(&self) -> bool;
}
impl IsVolatile for Register {
    #[inline]
    fn is_volatile(&self) -> bool {
        match *self {
            #[cfg(target_arch = "x86")]
            Self::EAX | Self::ECX | Self::EDX => true,
            #[cfg(target_arch = "x86_64")]
            Self::RCX | Self::RDX | Self::R8 | Self::R9 | Self::R10 | Self::R11 => true,
            _ => false
        }
    }
}