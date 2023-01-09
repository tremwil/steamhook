use iced_x86::*;
use std::collections::VecDeque;
use std::fmt::Display;
use std::ops::RangeBounds;
use std::{collections::{HashSet, HashMap}};
use std::ops::Bound::*;
use once_cell::sync::Lazy;
use thiserror::Error;

use crate::memory_utils::SafeDeref;
use crate::iced_extensions::*;

#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct CfgVertex {
    pub instr: Instruction,
    pub into: HashSet<u64>,
    pub out: HashSet<u64>,
}

impl CfgVertex {
    pub fn new(instr: Instruction) -> Self {
        Self {
            instr,
            into: HashSet::new(),
            out: HashSet::new()
        }
    }
}

#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct ControlFlowGraph {
    pub graph: HashMap<u64, CfgVertex>,
    pub root: u64,

    // kept for later analysis
    pub direct_calls: HashSet<u64>, 
    pub indirect_calls: HashSet<u64>,
    pub rets: HashSet<u64>,
    pub interrupts: HashSet<u64>
}

#[derive(Error, Debug)]
pub enum FlowAnalysisError {
    #[error("code out of bounds")]
    CodeOutOfBounds,
    #[error("invalid instruction")]
    InvalidInstruction
}

static EMPTY_SET : Lazy<HashSet<u64>> = Lazy::new(|| HashSet::new());

impl ControlFlowGraph {
    pub fn vertex_at(&self, ip: u64) -> Option<&CfgVertex> {
        self.graph.get(&ip)
    }

    pub fn instr_at(&self, ip: u64) -> Option<&Instruction> {
        self.graph.get(&ip).and_then(|v| Some(&v.instr))
    }

    pub fn into(&self, ip: u64) -> &HashSet<u64> {
        self.graph.get(&ip).and_then(|v| Some(&v.into)).unwrap_or(&EMPTY_SET)
    }

    pub fn out(&self, ip: u64) -> &HashSet<u64> {
        self.graph.get(&ip).and_then(|v| Some(&v.out)).unwrap_or(&EMPTY_SET)
    }

    pub unsafe fn build(&mut self, start: u64, code_bounds: &impl RangeBounds<u64>) -> Result<(), FlowAnalysisError> {
        self.graph.clear();
        self.direct_calls.clear();
        self.indirect_calls.clear();
        self.rets.clear();
        self.interrupts.clear();
        self.root = start;

        let code_start = match code_bounds.start_bound() {
            Unbounded => 0,
            Included(&b) => b,
            Excluded(&b) => b + 1
        };
        let code_end = match code_bounds.end_bound() {
            Unbounded => usize::MAX as u64,
            Included(&e) => e + 1,
            Excluded(&e) => e
        };

        let mut decoder = Decoder::with_ip(
            (std::mem::size_of::<usize>() * 8) as u32, 
            std::slice::from_raw_parts(code_start as *const u8, (code_end - code_start) as usize),
            code_start, DecoderOptions::NONE);

        let mut to_visit : Vec<(u64, Option<u64>)> = vec![(start, None)];

        // let mut formatter = NasmFormatter::new();
        
        while let Some((ip, from)) = to_visit.pop() {
            if !code_bounds.contains(&ip) {
                return Err(FlowAnalysisError::CodeOutOfBounds);
            }
            if let Some(v) = self.graph.get_mut(&ip) && let Some(f) = from {
                v.into.insert(f);
                continue;
            }

            decoder.set_position((ip - code_start) as usize).ok();
            decoder.set_ip(ip);

            let instr = decoder.decode();
            if instr.is_invalid() {
                return Err(FlowAnalysisError::InvalidInstruction);
            }

            // let mut output = String::new();
            // formatter.format(&instr, &mut output);
            // log::debug!("{:x} {}", ip, &output);

            let mut vert = CfgVertex::new(instr);
            if let Some(f) = from { 
                vert.into.insert(f);
            }

            // Handle constant jmp/jcc short/near
            if instr.is_jmp_short_or_near() || instr.is_jcc_short_or_near() {
                // If jcc, consider path obtained by not taking the jmp             
                if instr.is_jcc_short_or_near() {
                    vert.out.insert(instr.next_ip());
                }
                vert.out.insert(instr.near_branch_target());
            }
            // Handle switch table (will only work on 32-bit mode switches using SIB for now)
            else if instr.is_jmp_near_indirect() {
                if instr.op0_kind() == OpKind::Memory && instr.memory_displ_size() == 4 {
                    let mut switch_ptr = instr.memory_displacement32() as u64;
                    while code_bounds.contains(&switch_ptr) && code_bounds.contains(&(switch_ptr + 3)) {
                        let switch_block = *(switch_ptr as *const u32) as u64;
                        if !code_bounds.contains(&switch_block) {
                            break;
                        }
                        vert.out.insert(switch_block);
                        switch_ptr += 4;
                    }
                }
            }
            // Handle ret instruction
            else if instr.mnemonic() == Mnemonic::Ret {                
                self.rets.insert(ip);
            }
            // Handle interrupt
            else if instr.mnemonic() == Mnemonic::Int || instr.mnemonic() == Mnemonic::Int1 || instr.mnemonic() == Mnemonic::Int3 {
                self.interrupts.insert(ip);
            }
            // For the other instructions, control flow goes to the next instruction
            else {
                if instr.is_call_near() {
                    self.direct_calls.insert(ip);
                }
                else if instr.is_call_near_indirect() {
                    self.indirect_calls.insert(ip);
                }
                vert.out.insert(instr.next_ip());
            }

            // Add out edges to "to visit" stack
            for &v in &vert.out {
                to_visit.push((v, Some(ip)));
            }

            self.graph.insert(ip, vert);
        }

        Ok(())
    }

    /// Tries to find the register used to keep track of the current stack frame, if any.
    pub fn frame_register(&self) -> Option<Register> {
        let instr = &self.graph[&self.root].instr;
        if instr.mnemonic() == Mnemonic::Push
            && instr.op0_kind() == OpKind::Register
            && !instr.op0_register().is_volatile()
        {
            Some(instr.op0_register())
        }
        else {
            None
        }
    }

    /// Create a nested pointer tracking the provenance of operand `op` of instruction at IP `ip` up to a static address.
    /// 
    /// `before_analysis` is a closure called with the current current pointer and instruction about to be analyzed. 
    /// It can be used to dictate analyzer control flow and modify the computed pointer / instruction the analyzer will see.
    pub fn analyze_ptr(&self, ip: u64, op: u32, skip_first: bool, before_analysis: impl Fn(&mut AsmNestedPtr, &mut Instruction) -> AnalysisFlowCtrl) -> Option<AsmNestedPtr> {
        let mut ptr = AsmNestedPtr::default();

        // First, check the first instruction to initialize the pointer
        let mut v = &self.graph[&ip];
        Self::update_mov(&mut ptr, &v.instr, op).ok()?;

        let mut info_factory = InstructionInfoFactory::new();
        
        fn is_unsupported_write(access: OpAccess) -> bool {
            access == OpAccess::ReadCondWrite ||
            access == OpAccess::CondWrite
        }
        fn is_write(access: OpAccess) -> bool {
            is_unsupported_write(access) || access == OpAccess::Write
        }

        fn instr_fmt(ins: &Instruction) -> String {
            let mut s = String::new();
            let mut fmt = NasmFormatter::new();
            fmt.format(&ins, &mut s);
            s
        }

        if skip_first {          
            match v.into.iter().next() {
                Some(ip) => v = &self.graph[ip],
                None => return Some(ptr)
            }
        }
        loop {
            let mut instr = v.instr.clone();
            match before_analysis(&mut ptr, &mut instr) {
                AnalysisFlowCtrl::TerminateNone => return None,
                AnalysisFlowCtrl::TerminateSome => return Some(ptr),
                AnalysisFlowCtrl::SkipInstruction => {
                    match v.into.iter().next() {
                        Some(ip) => v = &self.graph[ip],
                        None => return Some(ptr)
                    }
                    continue;
                }
                AnalysisFlowCtrl::Continue => ()
            }

            let base = match ptr.base {
                PtrBase::Reg(r) => r,
                PtrBase::Addr(_) => return Some(ptr)
            };

            let info = info_factory.info(&instr);

            // Check if instruction performs a read/write which we cannot handle
            if let Some(r) = info.used_registers().iter().find_map(|r| 
                if r.register() == base && is_unsupported_write(r.access()) { Some(r) } else { None }
            ) {
                log::warn!("analyze_ptr does not support instruction at {:x} \"{}\": base access {:?}", instr.ip(), instr_fmt(&instr), r.access());
                return None;
            }
            if !ptr.offsets.is_empty() && info.used_memory().iter().any(|m|
                m.base() == base && ((is_write(m.access()) && m.index() != Register::None) 
                || (is_unsupported_write(m.access()) && m.displacement() as i32 == ptr.offsets[0]))
            ) {
                log::warn!("analyze_ptr does not support instruction {:x} \"{}\": invalid mem ref", instr.ip(), instr_fmt(&instr));
                return None;
            }
            
            let writes_base = (0..instr.op_count()).any(|op|
                instr.op_kind(op) == OpKind::Register 
                && instr.op_register(op) == base 
                && info.op_access(op).can_write()
            );

            let writes_top_mem = (0..instr.op_count()).any(|op| 
                !ptr.offsets.is_empty() 
                && instr.op_kind(op) == OpKind::Memory 
                && instr.memory_base() == base
                && instr.memory_index() == Register::None
                && instr.memory_displacement32() as i32 == ptr.offsets[0]
                && info.op_access(op).can_write()
            );

            // Handling both write types at once? Not defined
            if writes_base && writes_top_mem {
                log::warn!("analyze_ptr does not support instruction {:x} \"{}\": writing to base and [base + offset] simultaneously", instr.ip(), instr_fmt(&instr));
                return None;
            }
            else if writes_base || writes_top_mem { 
                let make_lea = |b: Register, imm: i64| {     
                    #[cfg(target_arch = "x86")]
                    let code = Code::Lea_r32_m;
                    #[cfg(target_arch = "x86_64")]
                    let code = Code::Lea_r64_m;
                    Instruction::with2(code, b, MemoryOperand::with_base_displ(b, imm))
                };

                let prv_ofs = if writes_top_mem { ptr.offsets.pop_front() } else { None }; 
                match instr.mnemonic() {
                    Mnemonic::Mov => {
                        Self::update_mov(&mut ptr, &instr, 1).ok()?;
                    }
                    Mnemonic::Lea => {
                        Self::update_lea(&mut ptr, &instr).ok()?;
                    }
                    Mnemonic::Add => {
                        if !instr.op1_kind().is_immediate() {                 
                            log::warn!("analyze_ptr does not support instruction {:x} \"{}\": non-immediate arithmetic", instr.ip(), instr_fmt(&instr));
                            return None; 
                        }
                        Self::update_lea(&mut ptr, &make_lea(base, instr.immediate(1) as i64).ok()?).ok()?;
                        if let Some(ofs) = prv_ofs {
                            ptr.offsets.push_front(ofs);
                        }
                    }
                    Mnemonic::Sub => {
                        if !instr.op1_kind().is_immediate() {                 
                            log::warn!("analyze_ptr does not support instruction {:x} \"{}\": non-immediate arithmetic", instr.ip(), instr_fmt(&instr));
                            return None; 
                        }
                        Self::update_lea(&mut ptr, &make_lea(base, -(instr.immediate(1) as i64)).ok()?).ok()?;
                        if let Some(ofs) = prv_ofs {
                            ptr.offsets.push_front(ofs);
                        }
                    }
                    _ => {
                        log::warn!("analyze_ptr does not support instruction {:x} \"{}\" with mnemonic {:?}", instr.ip(), instr_fmt(&instr), instr.mnemonic());
                        return None; 
                    }
                };  
            }
            
            match v.into.iter().next() {
                Some(ip) => v = &self.graph[ip],
                None => return Some(ptr)
            }
        }
    }

    fn update_mov(ptr: &mut AsmNestedPtr, instr: &Instruction, op: u32) -> Result<(), ()> {
        if op >= instr.op_count() {
            return Err(());
        }
        match instr.op_kind(op) {
            OpKind::Register => { ptr.base = PtrBase::Reg(instr.op_register(op)); },
            OpKind::Memory => {
                if instr.memory_index() != Register::None { return Err(()); }
                if instr.memory_base() == Register::None {
                    ptr.base = PtrBase::Addr(instr.virtual_address(op, 0, |_, _, _| Some(0)).ok_or(())? as isize);
                    ptr.offsets.push_front(0);
                }
                else {
                    ptr.base = PtrBase::Reg(instr.memory_base());
                    ptr.offsets.push_front(instr.memory_displacement32() as i32);
                }
            }
            k => {
                if k.is_immediate() {
                    ptr.base = PtrBase::Addr(instr.immediate(op) as isize);
                } else { return Err(()) };
            }
        };
        return Ok(())
    }

    fn update_lea(ptr: &mut AsmNestedPtr, instr: &Instruction) -> Result<(), ()> {
        if instr.memory_index() != Register::None { return Err(()); }

        if instr.memory_base() == Register::None {
            ptr.base = PtrBase::Addr(instr.virtual_address(1, 0, |_, _, _| Some(0)).ok_or(())? as isize);
        }
        else {
            ptr.base = PtrBase::Reg(instr.memory_base());
            if let Some(ofs) = ptr.offsets.get_mut(0) {
                *ofs += instr.memory_displacement32() as i32;
            }
            else {
                ptr.final_offset += instr.memory_displacement32() as isize;
            }
        }
        Ok(())
    }
}

/// Return value of [`ControlFlowGraph::analyze_ptr`]'s pre-instruction filter
/// controlling the next action of the analyzer.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum AnalysisFlowCtrl {
    /// Terminate the algorithm and return [`None`]. Use in a situation where 
    /// a result would be meaningless.
    TerminateNone,
    /// Terminate the algorithm and return [`Some(ptr)`]. Use for early stopping.
    TerminateSome,
    /// Keep running, but do not analyze the current instruction.
    SkipInstruction,
    /// Keep running and analyze the current instruction.
    Continue
}

impl From<Result<bool, ()>> for AnalysisFlowCtrl {
    fn from(value: Result<bool, ()>) -> Self {
        match value {
            Err(_) => AnalysisFlowCtrl::TerminateNone,
            Ok(true) => AnalysisFlowCtrl::TerminateSome,
            Ok(false) => AnalysisFlowCtrl::Continue
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum PtrBase {
    Reg(Register),
    Addr(isize)
}

impl PtrBase {
    pub fn is_reg(&self) -> bool {
        match self { PtrBase::Reg(_) => true, _ => false }
    }
    pub fn is_addr(&self) -> bool {
        match self { PtrBase::Addr(_) => true, _ => false }
    }
}

impl Default for PtrBase {
    fn default() -> Self {
        PtrBase::Addr(0)
    }
}

impl Display for PtrBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(target_pointer_width = "32")]
            PtrBase::Addr(a) => write!(f, "{:08x}", a),
            #[cfg(target_pointer_width = "64")]
            PtrBase::Addr(a) => write!(f, "{:016x}", a),
            PtrBase::Reg(r) => write!(f, "{:?}", r)
        }
    }
}

#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct AsmNestedPtr {
    pub base: PtrBase,
    pub final_offset: isize,
    pub offsets: VecDeque<i32>
}

impl AsmNestedPtr {
    pub fn eval(&self, base_value: isize) -> Option<isize> {
        let mut ptr: isize = match self.base {
            PtrBase::Reg(r) => base_value,
            PtrBase::Addr(a) => a
        };
        for &ofs in &self.offsets {
            ptr = ((ptr + ofs as isize) as *const isize).deref_safe()?;
        }
        Some(ptr + self.final_offset)
    }
}

impl Display for AsmNestedPtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = format!("{}", self.base);
        for &ofs in &self.offsets {
            s = if ofs == 0 { 
                format!("[{}]", s) 
            } else if ofs < 0 { 
                format!("[{}-{:x}]", s, -ofs) 
            } else { 
                format!("[{}+{:x}]", s, ofs)
            };
        }
        if self.final_offset < 0 { 
            s = format!("{}-{:x}", s, -self.final_offset);
        } else if self.final_offset > 0 { 
            s = format!("{}+{:x}", s, self.final_offset); 
        }
        write!(f, "{}", s)
    }
}