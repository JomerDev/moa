
use std::fmt;


pub type Register = u8;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Size {
    Byte,
    Word,
    Long,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Sign {
    Signed,
    Unsigned,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Direction {
    FromTarget,
    ToTarget,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ShiftDirection {
    Right,
    Left,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum XRegister {
    DReg(u8),
    AReg(u8),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum BaseRegister {
    None,
    PC,
    AReg(u8),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct IndexRegister {
    pub xreg: XRegister,
    pub scale: u8,
    pub size: Size,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RegOrImmediate {
    DReg(u8),
    Immediate(u8),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ControlRegister {
    VBR,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Condition {
    True,
    False,
    High,
    LowOrSame,
    CarryClear,
    CarrySet,
    NotEqual,
    Equal,
    OverflowClear,
    OverflowSet,
    Plus,
    Minus,
    GreaterThanOrEqual,
    LessThan,
    GreaterThan,
    LessThanOrEqual,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Target {
    Immediate(u32),
    DirectDReg(Register),
    DirectAReg(Register),
    IndirectAReg(Register),
    IndirectARegInc(Register),
    IndirectARegDec(Register),
    IndirectRegOffset(BaseRegister, Option<IndexRegister>, i32),
    IndirectMemoryPreindexed(BaseRegister, Option<IndexRegister>, i32, i32),
    IndirectMemoryPostindexed(BaseRegister, Option<IndexRegister>, i32, i32),
    IndirectMemory(u32),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Instruction {
    ABCD(Target, Target),
    ADD(Target, Target, Size),
    ADDX(Target, Target, Size),
    AND(Target, Target, Size),
    ANDtoCCR(u8),
    ANDtoSR(u16),
    ASd(Target, Target, Size, ShiftDirection),

    Bcc(Condition, i32),
    BRA(i32),
    BSR(i32),
    BCHG(Target, Target, Size),
    BCLR(Target, Target, Size),
    BSET(Target, Target, Size),
    BTST(Target, Target, Size),
    BFCHG(Target, RegOrImmediate, RegOrImmediate),
    BFCLR(Target, RegOrImmediate, RegOrImmediate),
    BFEXTS(Target, RegOrImmediate, RegOrImmediate, Register),
    BFEXTU(Target, RegOrImmediate, RegOrImmediate, Register),
    BFFFO(Target, RegOrImmediate, RegOrImmediate, Register),
    BFINS(Register, Target, RegOrImmediate, RegOrImmediate),
    BFSET(Target, RegOrImmediate, RegOrImmediate),
    BFTST(Target, RegOrImmediate, RegOrImmediate),
    BKPT(u8),

    CHK(Target, Register, Size),
    CLR(Target, Size),
    CMP(Target, Target, Size),
    CMPA(Target, Register, Size),

    DBcc(Condition, Register, i16),
    DIVW(Target, Register, Sign),
    DIVL(Target, Option<Register>, Register, Sign),

    EOR(Target, Target, Size),
    EORtoCCR(u8),
    EORtoSR(u16),
    EXG(Target, Target),
    EXT(Register, Size, Size),

    ILLEGAL,

    JMP(Target),
    JSR(Target),

    LEA(Target, Register),
    LINK(Register, i32),
    LSd(Target, Target, Size, ShiftDirection),

    MOVE(Target, Target, Size),
    MOVEA(Target, Register, Size),
    MOVEfromSR(Target),
    MOVEtoSR(Target),
    MOVEfromCCR(Target),
    MOVEtoCCR(Target),
    MOVEC(Target, ControlRegister, Direction),
    MOVEM(Target, Size, Direction, u16),
    MOVEP(Register, Target, Size, Direction),
    MOVEQ(u8, Register),
    MOVEUSP(Target, Direction),
    MULW(Target, Register, Sign),
    MULL(Target, Option<Register>, Register, Sign),

    NBCD(Target),
    NEG(Target, Size),
    NEGX(Target, Size),

    NOP,
    NOT(Target, Size),

    OR(Target, Target, Size),
    ORtoCCR(u8),
    ORtoSR(u16),

    PEA(Target),

    RESET,
    ROd(Target, Target, Size, ShiftDirection),
    ROXd(Target, Target, Size, ShiftDirection),
    RTE,
    RTR,
    RTS,
    RTD(i16),

    SBCD(Target, Target),
    Scc(Condition, Target),
    STOP(u16),
    SUB(Target, Target, Size),
    SUBX(Target, Target, Size),
    SWAP(Register),

    TAS(Target),
    TST(Target, Size),
    TRAP(u8),
    TRAPV,

    UNLK(Register),
}

pub fn sign_extend_to_long(value: u32, from: Size) -> i32 {
    match from {
        Size::Byte => ((value as u8) as i8) as i32,
        Size::Word => ((value as u16) as i16) as i32,
        Size::Long => value as i32,
    }
}

impl Size {
    pub fn in_bytes(&self) -> u32 {
        match self {
            Size::Byte => 1,
            Size::Word => 2,
            Size::Long => 4,
        }
    }

    pub fn in_bits(&self) -> u32 {
        match self {
            Size::Byte => 8,
            Size::Word => 16,
            Size::Long => 32,
        }
    }
}


impl fmt::Display for Sign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sign::Signed => write!(f, "s"),
            Sign::Unsigned => write!(f, "u"),
        }
    }
}

impl fmt::Display for ShiftDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShiftDirection::Right => write!(f, "r"),
            ShiftDirection::Left => write!(f, "l"),
        }
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Size::Byte => write!(f, "b"),
            Size::Word => write!(f, "w"),
            Size::Long => write!(f, "l"),
        }
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Condition::True => write!(f, "t"),
            Condition::False => write!(f, "f"),
            Condition::High => write!(f, "hi"),
            Condition::LowOrSame => write!(f, "ls"),
            Condition::CarryClear => write!(f, "cc"),
            Condition::CarrySet => write!(f, "cs"),
            Condition::NotEqual => write!(f, "ne"),
            Condition::Equal => write!(f, "eq"),
            Condition::OverflowClear => write!(f, "oc"),
            Condition::OverflowSet => write!(f, "os"),
            Condition::Plus => write!(f, "p"),
            Condition::Minus => write!(f, "m"),
            Condition::GreaterThanOrEqual => write!(f, "ge"),
            Condition::LessThan => write!(f, "lt"),
            Condition::GreaterThan => write!(f, "gt"),
            Condition::LessThanOrEqual => write!(f, "le"),
        }
    }
}

impl fmt::Display for ControlRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlRegister::VBR => write!(f, "%vbr"),
        }
    }
}

impl fmt::Display for XRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XRegister::DReg(reg) => write!(f, "d{}", reg),
            XRegister::AReg(reg) => write!(f, "a{}", reg),
        }
    }
}

impl fmt::Display for BaseRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseRegister::None => Ok(()),
            BaseRegister::PC => write!(f, "%pc + "),
            BaseRegister::AReg(reg) => write!(f, "%a{} + ", reg),
        }
    }
}

fn fmt_index_disp(index: &Option<IndexRegister>) -> String {
    match index {
        Some(index) => {
            let mut result = format!("%{}", index.xreg);
            if index.scale != 0 {
                result += &format!("<< {}", index.scale);
            }
            result += " + ";
            result
        },
        None => "".to_string(),
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Immediate(value) => write!(f, "#{:08x}", value),
            Target::DirectDReg(reg) => write!(f, "%d{}", reg),
            Target::DirectAReg(reg) => write!(f, "%a{}", reg),
            Target::IndirectAReg(reg) => write!(f, "(%a{})", reg),
            Target::IndirectARegInc(reg) => write!(f, "(%a{})+", reg),
            Target::IndirectARegDec(reg) => write!(f, "-(%a{})", reg),
            Target::IndirectRegOffset(base_reg, index_reg, offset) => {
                let index_str = fmt_index_disp(index_reg);
                write!(f, "({}{}#{:04x})", base_reg, index_str, offset)
            },
            Target::IndirectMemoryPreindexed(base_reg, index_reg, base_disp, outer_disp) => {
                let index_str = fmt_index_disp(index_reg);
                write!(f, "([{}{}#{:08x}] + #{:08x})", base_reg, index_str, base_disp, outer_disp)
            },
            Target::IndirectMemoryPostindexed(base_reg, index_reg, base_disp, outer_disp) => {
                let index_str = fmt_index_disp(index_reg);
                write!(f, "([{}#{:08x}]{} + #{:08x})", base_reg, base_disp, index_str, outer_disp)
            },
            Target::IndirectMemory(value) => write!(f, "(#{:08x})", value),
        }
    }
}

fn fmt_movem_mask(mask: u16) -> String {
    format!("something")
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::ABCD(src, dest) => write!(f, "abcd\t{}, {}", src, dest),
            Instruction::ADD(src, dest, size) => write!(f, "add{}\t{}, {}", size, src, dest),
            Instruction::AND(src, dest, size) => write!(f, "and{}\t{}, {}", size, src, dest),
            Instruction::ANDtoCCR(value) => write!(f, "andb\t{:02x}, %ccr", value),
            Instruction::ANDtoSR(value) => write!(f, "andw\t{:04x}, %sr", value),
            Instruction::ASd(src, dest, size, dir) => write!(f, "as{}{}\t{}, {}", dir, size, src, dest),

            Instruction::Bcc(cond, offset) => write!(f, "b{}\t{}", cond, offset),
            Instruction::BRA(offset) => write!(f, "bra\t{}", offset),
            Instruction::BSR(offset) => write!(f, "bra\t{}", offset),
            Instruction::BCHG(src, dest, size) => write!(f, "bchg{}\t{}, {}", size, src, dest),
            Instruction::BCLR(src, dest, size) => write!(f, "bclr{}\t{}, {}", size, src, dest),
            Instruction::BSET(src, dest, size) => write!(f, "bset{}\t{}, {}", size, src, dest),
            Instruction::BTST(src, dest, size) => write!(f, "btst{}\t{}, {}", size, src, dest),
            //Instruction::BKPT(value),

            Instruction::CHK(target, reg, size) => write!(f, "chk{}\t{}, %d{}", size, target, reg),
            Instruction::CLR(target, size) => write!(f, "clr{}\t{}", size, target),
            Instruction::CMP(src, dest, size) => write!(f, "cmp{}\t{}, {}", size, src, dest),
            Instruction::CMPA(target, reg, size) => write!(f, "cmpa{}\t{}, %a{}", size, target, reg),

            Instruction::DBcc(cond, reg, offset) => write!(f, "db{}\t%d{}, {}", cond, reg, offset),
            Instruction::DIVW(src, dest, sign) => write!(f, "div{}w\t{}, %d{}", sign, src, dest),
            Instruction::DIVL(src, desth, destl, sign) => {
                let opt_reg = desth.map(|reg| format!("%d{}:", reg)).unwrap_or("".to_string());
                write!(f, "div{}l\t{}, {}%d{}", sign, src, opt_reg, destl)
            },

            Instruction::EOR(src, dest, size) => write!(f, "eor{}\t{}, {}", size, src, dest),
            Instruction::EORtoCCR(value) => write!(f, "eorb\t{:02x}, %ccr", value),
            Instruction::EORtoSR(value) => write!(f, "eorw\t{:04x}, %sr", value),
            Instruction::EXG(src, dest) => write!(f, "exg\t{}, {}", src, dest),
            Instruction::EXT(reg, from_size, to_size) => write!(f, "ext{}{}\t%d{}", from_size, to_size, reg),

            Instruction::ILLEGAL => write!(f, "illegal"),

            Instruction::JMP(target) => write!(f, "jmp\t{}", target),
            Instruction::JSR(target) => write!(f, "jsr\t{}", target),

            Instruction::LEA(target, reg) => write!(f, "lea\t{}, %a{}", target, reg),
            Instruction::LINK(reg, offset) => write!(f, "link\t%a{}, {}", reg, offset),
            Instruction::LSd(src, dest, size, dir) => write!(f, "ls{}{}\t{}, {}", dir, size, src, dest),

            Instruction::MOVE(src, dest, size) => write!(f, "move{}\t{}, {}", size, src, dest),
            Instruction::MOVEA(target, reg, size) => write!(f, "movea{}\t{}, %a{}", size, target, reg),
            Instruction::MOVEfromSR(target) => write!(f, "movew\t%sr, {}", target),
            Instruction::MOVEtoSR(target) => write!(f, "movew\t{}, %sr", target),
            Instruction::MOVEfromCCR(target) => write!(f, "moveb\t%ccr, {}", target),
            Instruction::MOVEtoCCR(target) => write!(f, "moveb\t{}, %ccr", target),
            Instruction::MOVEC(target, reg, dir) => match dir {
                Direction::ToTarget => write!(f, "movec\t{}, {}", reg, target),
                Direction::FromTarget => write!(f, "movec\t{}, {}", target, reg),
            },
            Instruction::MOVEM(target, size, dir, mask) => match dir {
                Direction::ToTarget => write!(f, "movem{}\t{}, {}", size, fmt_movem_mask(*mask), target),
                Direction::FromTarget => write!(f, "movem{}\t{}, {}", size, target, fmt_movem_mask(*mask)),
            },
            Instruction::MOVEP(reg, target, size, dir) => match dir {
                Direction::ToTarget => write!(f, "movep{}\t%d{}, {}", size, reg, target),
                Direction::FromTarget => write!(f, "movep{}\t{}, %d{}", size, target, reg),
            },
            Instruction::MOVEQ(value, reg) => write!(f, "moveq\t#{:02x}, %d{}", value, reg),
            Instruction::MOVEUSP(target, dir) => match dir {
                Direction::ToTarget => write!(f, "movel\t%usp, {}", target),
                Direction::FromTarget => write!(f, "movel\t{}, %usp", target),
            },
            Instruction::MULW(src, dest, sign) => write!(f, "mul{}w\t{}, %d{}", sign, src, dest),
            Instruction::MULL(src, desth, destl, sign) => {
                let opt_reg = desth.map(|reg| format!("%d{}:", reg)).unwrap_or("".to_string());
                write!(f, "mul{}l\t{}, {}%d{}", sign, src, opt_reg, destl)
            },

            Instruction::NBCD(target) => write!(f, "nbcd\t{}", target),
            Instruction::NEG(target, size) => write!(f, "neg{}\t{}", size, target),
            Instruction::NEGX(target, size) => write!(f, "negx{}\t{}", size, target),

            Instruction::NOP => write!(f, "nop"),
            Instruction::NOT(target, size) => write!(f, "not{}\t{}", size, target),

            Instruction::OR(src, dest, size) => write!(f, "or{}\t{}, {}", size, src, dest),
            Instruction::ORtoCCR(value) => write!(f, "orb\t{:02x}, %ccr", value),
            Instruction::ORtoSR(value) => write!(f, "orw\t{:04x}, %sr", value),

            Instruction::PEA(target) => write!(f, "pea\t{}", target),

            Instruction::RESET => write!(f, "reset"),
            Instruction::ROd(src, dest, size, dir) => write!(f, "ro{}{}\t{}, {}", dir, size, src, dest),
            Instruction::ROXd(src, dest, size, dir) => write!(f, "rox{}{}\t{}, {}", dir, size, src, dest),
            Instruction::RTE => write!(f, "rte"),
            Instruction::RTR => write!(f, "rtr"),
            Instruction::RTS => write!(f, "rts"),
            Instruction::RTD(offset) => write!(f, "rtd\t{}", offset),

            Instruction::SBCD(src, dest) => write!(f, "sbcd\t{}, {}", src, dest),
            Instruction::Scc(cond, target) => write!(f, "s{}\t{}", cond, target),
            Instruction::STOP(value) => write!(f, "stop\t#{:04x}", value),
            Instruction::SUB(src, dest, size) => write!(f, "sub{}\t{}, {}", size, src, dest),
            Instruction::SWAP(reg) => write!(f, "swap\t%d{}", reg),

            Instruction::TAS(target) => write!(f, "tas\t{}", target),
            Instruction::TST(target, size) => write!(f, "tst{}\t{}", size, target),
            Instruction::TRAP(num) => write!(f, "trap\t{}", num),
            Instruction::TRAPV => write!(f, "trapv"),

            Instruction::UNLK(reg) => write!(f, "unlk\t%a{}", reg),
            _ => write!(f, "UNIMPL"),
        }
    }
}
