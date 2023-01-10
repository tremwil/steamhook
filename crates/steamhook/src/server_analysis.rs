use std::collections::{VecDeque, HashMap, HashSet};

use pelite::pe::{Pe, Va};
use thiserror::Error;
use iced_x86::*;
use bounded_vec_deque::*;
use crate::cfg::*;
use super::{util::{*, self}, steam_hook::InterfaceBase};

use crate::vtable_scan::ModuleId;
use windows::{Win32::{System::LibraryLoader::GetProcAddress, Foundation::HINSTANCE}, core::PCSTR};

// Third pass: Analyze the dispatcher and extract function names and vtable offsets.
// This should be relatively easy: 
// - Find indirect calls on first argument (check for mov ecx, [ebp + const] behind call)
// - Compute vtable offset by either adding indirect displacement or from prevous mov dword ptr []
// - Scan upwards until call to Steam_IPCRecv_Start
// - Scan downwards for 2 PUSH instructions with fn and interface name

#[derive(Error, Debug)]
pub enum CallDispatcherAnalysisError {
    #[error("unable to fetch steamclient DLL .text section bounds")]
    CodeBounds,
    #[error("unable to find address of TIER0_S.dll+ETW_Steamworks_IPCRecv_Start")]
    IPCRecvStartNotFound,
    #[error("control flow analysis errror: {0:?}")]
    FlowAnalysisError(#[from] FlowAnalysisError),
    #[error("no frame register found for function {0:x}")]
    NoFrameRegister(u64),
    #[error("two distinct interface names encountered at call {0:x}: \"{1}\", \"{2}\"")]
    ConflictingInterfaceNames(u64, &'static str, &'static str),
    #[error("unnamed IPC call at address {0:x}")]
    MissingName(u64),
    #[error("call ID not found for {1}::{2} at address {0:x}")]
    MissingCallId(u64, &'static str, &'static str),
    #[error("unspecified error")]
    Unspecified
}

#[derive(Default, Clone)]
pub struct CallDispatcherData {
    pub interface: &'static str,
    pub methods: Vec<CallData>
}

#[derive(Default, Clone)]
pub struct CallData {
    pub name: &'static str,
    pub vmt_offset: u32,
    pub call_id: u32
}

pub fn analyze_call_dispatcher(fun: u64) -> Result<CallDispatcherData, CallDispatcherAnalysisError> {
    let pe = steam_client_pe().ok_or(CallDispatcherAnalysisError::CodeBounds)?;
    let code_bounds = client_code_bounds().ok_or(CallDispatcherAnalysisError::CodeBounds)?;
    if !code_bounds.contains(&fun) {
        return Err(FlowAnalysisError::CodeOutOfBounds.into());
    }

    let tier0_handle = "tier0_s.dll".get_handle().ok_or(CallDispatcherAnalysisError::IPCRecvStartNotFound)?;
    let ipcrecv_start = unsafe {
        GetProcAddress(HINSTANCE(tier0_handle as isize), PCSTR(b"ETW_Steamworks_IPCRecv_Start\0" as *const u8))
        .ok_or(CallDispatcherAnalysisError::IPCRecvStartNotFound)?
    } as u64;

    let mut results =  CallDispatcherData::default();

    let mut cfg = ControlFlowGraph::default();
    unsafe { cfg.build(fun, &code_bounds)? };

    let frame_reg = cfg.frame_register()
        .ok_or(CallDispatcherAnalysisError::NoFrameRegister(fun))?;

    let mut vmt_indices: HashSet<u32> = HashSet::new();

    for &icall in &cfg.indirect_calls {
        // First check if this is a virtual call
        let vcall_info = match virtual_call_info(&cfg, icall) {
            None => continue,
            Some(v) => v
        };

        // Only care about virtual calls on the first parameter, i.e. instruction is 
        // MOV ECX, [EBP + 8] (first parameter)
        let mut v = &cfg.graph[&vcall_info.thisptr_instr_ip];
        if v.instr.mnemonic() != Mnemonic::Mov 
            || v.instr.op1_kind() != OpKind::Memory
            || v.instr.memory_base() != frame_reg
            || v.instr.memory_displacement32() != 8
        {
            continue;
        }

        // Lookbehind until we find the IPCRecv_Start call, keeping track of the last 2 
        // PUSH (string) 
        let mut call_data = CallData::default();
        let mut str_refs: BoundedVecDeque<&'static str> = BoundedVecDeque::new(2);
        loop {
            let ip = *v.into.iter().next().ok_or(CallDispatcherAnalysisError::MissingName(icall))?;
            v = &cfg.graph[&ip];

            // Push instruction
            if v.instr.mnemonic() == Mnemonic::Push 
                && v.instr.op0_kind() == OpKind::Immediate32
                && let Some(str) = read_nt_static_str(&pe, v.instr.immediate32() as u64) 
            {
                str_refs.push_back(str);    
            }

            // IPCRecv_Start indirect call found
            if v.instr.is_call_near_indirect()
                && let Some(tgt) = v.instr.virtual_address(0, 0, |_,_,_| Some(0))
                && let Some(ptr) = (tgt as *const u32).deref_safe()
                && ptr as u64 == ipcrecv_start
            {
                if str_refs.len() != 2 {
                    return Err(CallDispatcherAnalysisError::MissingName(icall))
                }
                if results.interface.is_empty() {
                    results.interface = str_refs[0];
                }
                else if results.interface != str_refs[0] {
                    return Err(CallDispatcherAnalysisError::ConflictingInterfaceNames(
                        icall, results.interface, str_refs[0]))
                }

                call_data.name = str_refs[1];
                call_data.vmt_offset = vcall_info.index;
                break;
            } 
        }

        // Lookbehind until we find a CMP instruction. The second operand immediate is
        // the IPC call ID.
        loop {
            let ip = *v.into.iter().next().ok_or(CallDispatcherAnalysisError::MissingCallId(
                icall, results.interface, call_data.name))?;
            v = &cfg.graph[&ip];

            if v.instr.mnemonic() == Mnemonic::Cmp && v.instr.op1_kind() == OpKind::Immediate32 {
                call_data.call_id = v.instr.immediate32();
                break;
            }
        }

        if !vmt_indices.insert(call_data.vmt_offset) {
            log::warn!("analyze_call_dispatcher: duplicate vmt {}: {}::{}", call_data.vmt_offset, results.interface, call_data.name);
        }

        results.methods.push(call_data);
    }

    Ok(results)
}


// Attempt to find a nested pointer to a Steam interface from CSteamEngine / CUser.
// The first argument can be stored in 5 ways:
// - Inline in the CSteamEngine (*often* virtual inheritance)
// - Pointer in the CSteamEngine
// - Inline in the CUser (virtual inheritance)
// - Pointer in the CUser
// - Pointer in the CUser with virtual inheritance
// This argument is the "instance" of our global server interface.
// We must go case by case and fetch it.
pub fn analyze_interface_ptr(cfg: &ControlFlowGraph, param_ip: u64, steam_engine_frame_pos: i32) -> Option<(InterfaceBase, AsmNestedPtr)> {
    let frame_reg = cfg.frame_register()?;
    let mut v = cfg.graph.get(&param_ip)?;

    let mut ptr = cfg.analyze_ptr(param_ip, 0, false, |ptr, ins| {
        if let PtrBase::Reg(r) = ptr.base {
            // Pointer to persistent var => CSteamEngine or CUser 
            if !r.is_caller_saved() {
                AnalysisFlowCtrl::TerminateSome
            }
            // When this happens, pointer is to the CUser, which should be in ECX before it. 
            // Modify the pointer accordingly
            else if r == Register::EAX && ins.is_call_near_indirect() {
                // Assume the virtual call is the identity (Cuser -> CUser). 
                // This is true for the call to +0x94, but the call to +0x98 is NULL (no instance).
                // Hence an incorrect pointer may be computed for +0x98 interfaces. 
                // 
                // TODO: follow virtual call and get proper offset
                AnalysisFlowCtrl::TerminateSome
            }
            // Instruction is an AND -- this happens because of weird "optimized" pointer-zeroing for virtual inheritance
            // to "fix" this, we check if the AND is preceded by SBB, and choose the register that isn't the SBB one
            // dirty but works
            else if ins.mnemonic() == Mnemonic::And && ins.op0_register() == r {
                if ins.op1_kind() != OpKind::Register {
                    return AnalysisFlowCtrl::TerminateNone;
                }
                let prv = match cfg.graph[&ins.ip()].into.iter().next() {
                    None => return AnalysisFlowCtrl::TerminateNone,
                    Some(ip) => &cfg.graph[ip].instr
                };
                if prv.mnemonic() == Mnemonic::Sbb && prv.op0_register() == r {
                    ptr.base = PtrBase::Reg(ins.op1_register());
                }
                AnalysisFlowCtrl::SkipInstruction
            }
            else {
                AnalysisFlowCtrl::Continue
            }
        }
        else {
            AnalysisFlowCtrl::TerminateSome
        }
    })?;

    Some((match ptr.base {
        PtrBase::Addr(_) => InterfaceBase::Static,
        PtrBase::Reg(r) => {
            if r == frame_reg && ptr.offsets.get(0) == Some(&steam_engine_frame_pos) {
                // Replace stack location by non-stack for evaluation with CSteamEngine ptr
                ptr.base = PtrBase::Reg(Register::ECX);
                ptr.offsets.pop_front();
                InterfaceBase::Engine
            }
            else {
                InterfaceBase::User
            }
        }
    }, ptr))
}

#[derive(Clone, Copy, Eq, PartialEq, Default)]
struct VirtualCallInfo {
    thisptr_instr_ip: u64,
    index: u32
}

/// Analyze an indirect call instruction that may be a virtual call, and if it is return:
/// - The IP of the instruction writing to ECX
/// - The index of the method in the virtual function table
fn virtual_call_info(cfg: &ControlFlowGraph, indirect_call: u64) -> Option<VirtualCallInfo> {
    let mut v = cfg.graph.get(&indirect_call)?;

    let mut call_info = VirtualCallInfo::default();

    if !v.instr.is_call_near_indirect() {
        return None;
    }
    // Instruction is not of the form CALL REG or CALL REG [X + OFFSET]
    if v.instr.op0_kind() != OpKind::Register && 
        !(v.instr.op0_kind() == OpKind::Memory && v.instr.memory_base() != Register::None) 
    {
        return None;
    }

    let mut info_factory = InstructionInfoFactory::new();
    let mut thisptr_reg_op : Option<u32> = None;
    loop {
        let ip = *v.into.iter().next()?;
        v = &cfg.graph[&ip];

        if v.instr.mnemonic() == Mnemonic::Call {
            return None;
        }

        let info = info_factory.info(&v.instr);
        let writes_ecx = info.used_registers().iter().any(|r| 
            r.register() == Register::ECX && r.access() == OpAccess::Write);

        if writes_ecx {
            call_info.thisptr_instr_ip = ip;
            thisptr_reg_op = (0..v.instr.op_count()).find(|&op|
                v.instr.op_register(op) == Register::ECX && info.op_access(op) == OpAccess::Write
            );
            break;
        }
    }
    if thisptr_reg_op.is_none() {
        log::warn!("Potential virtual call at {:x} has unsupported ECX write", indirect_call);
        return None;
    }

    let init_ptr = AsmNestedPtr { base: PtrBase::Reg(Register::ECX), final_offset: 0, offsets: VecDeque::new() };
    let ecx_ptr = cfg.analyze_ptr(call_info.thisptr_instr_ip, thisptr_reg_op.unwrap(), false, |ptr, _| Ok(ptr != &init_ptr).into())?;

    let vtbl_ptr = cfg.analyze_ptr(indirect_call, 0, true, |ptr, ins| {
        if ptr.final_offset != 0 { 
            return AnalysisFlowCtrl::TerminateNone;
        } 
        match ptr.base == ecx_ptr.base && ptr.offsets.get(0) == ecx_ptr.offsets.get(0) {
            true => Ok(true),
            false => if ins.mnemonic() == Mnemonic::Call { Err(()) } else { Ok(false) }
        }.into()
    })?;

    call_info.index = (vtbl_ptr.offsets.iter().last()? / 4) as u32;
    Some(call_info)
}