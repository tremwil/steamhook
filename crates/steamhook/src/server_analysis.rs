use std::{collections::{VecDeque, HashSet}, ops::Range};
use itertools::Itertools;
use windows::{Win32::{System::LibraryLoader::GetProcAddress, Foundation::HINSTANCE}, core::PCSTR};

use thiserror::Error;
use iced_x86::*;
use bounded_vec_deque::*;

use super::code_analysis::*;
use super::{memory_utils::*, steamhook::InterfaceBase};
use super::iced_extensions::IsVolatile;
use super::vtable_scan::ModuleId;

/// Index of interface dispatcher in CSteamEngine vtable
const ENGINE_INTERFACE_DISPATCH_VMT_OFFSET: isize = 0x12;

/// Prologue of the UtlRbTree::IndexOf method
const RBTREE_INDEX_OF_FN_AOB : &'static [u8] = &[
    0x55, 0x8b, 0xec, 0x83, 0xec, 0x08, 0x53, 0x8b, 
    0xd9, 0x33, 0xc0, 0x56, 0x57, 0x89, 0x45, 0xfc, 
    0x8b, 0x7b, 0x10, 0x83, 0xef, 0x01
];
/// Stack frame offset of the CSteamEngine instance in the interface dispatcher function
/// 
/// ## TODO
/// Get this from static analysis
const INTERFACE_DISPATCH_STEAM_ENGINE_FRAME_OFFSET: i32 = -4;

// Third pass: Analyze the dispatcher and extract function names and vtable offsets.
// This should be relatively easy: 
// - Find indirect calls on first argument (check for mov ecx, [ebp + const] behind call)
// - Compute vtable offset by either adding indirect displacement or from prevous mov dword ptr []
// - Scan upwards until call to Steam_IPCRecv_Start
// - Scan downwards for 2 PUSH instructions with fn and interface name

#[derive(Error, Debug)]
pub enum ServerAnalysisError {
    #[error("unable to fetch steamclient DLL .text section bounds")]
    CodeBounds,
    #[error("invalid CSteamEngine pointer")]
    CSteamEngineBadPtr,
    #[error("failed to fetch IPC interface dispatcher via CSteamEngine vtable")]
    IPCDispatcherBadPtr,
    #[error("CUser offset not found")]
    UserOffsetNotFound,
    #[error("invalid CUser list pointer (offset 0x{0:x})")]
    UserListBadPtr(isize),
    #[error("invalid CUser pointer (offset 0x{0:x})")]
    UserBadPtr(isize),
    #[error("unable to find address of TIER0_S.dll+ETW_Steamworks_IPCRecv_Start")]
    IPCRecvStartNotFound,
    #[error("control flow analysis errror: {0:?}")]
    FlowAnalysisError(#[from] FlowAnalysisError),
    #[error("no frame register found for function {0:x}")]
    NoFrameRegister(u64),
    #[error("two distinct interface names encountered at IPC call {0:x}: \"{1}\", \"{2}\"")]
    ConflictingInterfaceNames(u64, &'static str, &'static str),
    #[error("unnamed IPC call at address {0:x}")]
    MissingName(u64),
    #[error("IPC call ID not found for {1}::{2} at address {0:x}")]
    MissingCallId(u64, &'static str, &'static str),
    #[error("pointer analysis for IPC call dispatcher failed for instruction at 0x{0:x}")]
    PointerAnalysisFailed(u64),
    #[error("{0}")]
    Other(String)
}

#[derive(Default, Clone)]
pub(crate) struct InterfaceDispatcherData {
    pub cfg: ControlFlowGraph,
    pub user_offset: isize,
    pub call_dispatchers: Vec<(u64, u64)>
}

#[derive(Default, Clone)]
pub(crate) struct CallDispatcherData {
    pub interface: &'static str,
    pub methods: Vec<CallData>
}

#[derive(Default, Clone)]
pub(crate) struct CallData {
    pub name: &'static str,
    pub vmt_offset: u32,
    pub call_id: u32
}

/// Analyzes CSteamEngine's IPC interface dispatch function, extracting 
pub(crate) fn analyze_interface_dispatcher(steam_engine_ins: usize) -> Result<InterfaceDispatcherData, ServerAnalysisError> {
    let text_bounds = client_code_bounds().ok_or(ServerAnalysisError::CodeBounds)?;
    let ipc_dispatch = unsafe { (steam_engine_ins as *const *const usize)
        .try_deref().ok_or(ServerAnalysisError::IPCDispatcherBadPtr)?   // CSteamEngine::vftable_ptr
        .offset(ENGINE_INTERFACE_DISPATCH_VMT_OFFSET)
        .try_deref().ok_or(ServerAnalysisError::IPCDispatcherBadPtr)?   // CSteamEngine::IPCDispatch
    };

    log::debug!("main IPC dispatcher: {:x}", ipc_dispatch);
    
    // Analyze control flow of the IPC dispatcher
    let mut cfg = ControlFlowGraph::default();
    unsafe { 
        cfg.build(ipc_dispatch as u64, &text_bounds)?; 
    }
    let frame_reg = cfg.frame_register().ok_or(
        ServerAnalysisError::NoFrameRegister(ipc_dispatch as u64)
    )?;

    // Try to find the global CUser instance offset
    let user_offset = find_user_list_offset(&cfg, &text_bounds)?;

    // Look for candidate IPC call dispatcher functions
    // Also keep track of the IP of the instruction that pushes their first argument
    let call_dispatchers = cfg.direct_calls.iter().filter_map(|c| {
        let mut v = &cfg.graph[c];
        let mut first_arg = 0u64;
        let mut acnt = 0;

        loop {
            let ip = *v.into.iter().next()?;
            v = &cfg.graph[&ip];

            if v.instr.mnemonic() == Mnemonic::Call {
                return None;
            }
            else if v.instr.mnemonic() == Mnemonic::Push {
                acnt += 1;
                if acnt == 1 {
                    first_arg = ip;
                }
                if acnt == 3 { // All dispatchers take the buffer (param_2) as a third arg
                    if v.instr.op0_kind() == OpKind::Memory && 
                        v.instr.memory_base() == frame_reg && 
                        v.instr.memory_displacement32() == 0xC 
                    {
                        return Some((cfg.graph[c].instr.near_branch_target(), first_arg));
                    }
                    return None;
                }
            }
        }
    }).collect_vec();

    Ok(InterfaceDispatcherData { 
        cfg, 
        user_offset, 
        call_dispatchers 
    })
}

/// Find the offset of the CUser list (actually a red-black tree) in the CSteamEngine instance by: 
/// - Finding `RBTree::IndexOf` method by checking prologue bytes
/// - Getting the offset of the `CUser` red-black tree in `CSteamEngine` by 
///   looking at the `LEA ECX, [REG + OFFSET]` instruction of the `IndexOf` call
/// - Fetching the first `CUser` instance in the tree
pub(crate) fn find_user_list_offset(cfg: &ControlFlowGraph, text_bounds: &Range<u64>) -> Result<isize, ServerAnalysisError> {
        let cuser_offset = cfg.direct_calls.iter().find_map(|c| {
            let mut v = &cfg.graph[c];
            let target = v.instr.near_branch_target();

            if !text_bounds.contains(&(target + RBTREE_INDEX_OF_FN_AOB.len() as u64)) {
                return None;
            }
            let target_prologue = unsafe { 
                std::slice::from_raw_parts(target as *mut u8, RBTREE_INDEX_OF_FN_AOB.len())
            };
            if target_prologue != RBTREE_INDEX_OF_FN_AOB {
                return None;
            }
            loop {
                let ip = v.into.iter().next()?;
                v = &cfg.graph[&ip];

                if v.instr.mnemonic() == Mnemonic::Call { return None; } 
                else if v.instr.mnemonic() == Mnemonic::Lea
                    && v.instr.op0_register() == Register::ECX
                    && v.instr.op1_kind() == OpKind::Memory
                {
                    return Some(v.instr.memory_displacement32());
                }
            }
        }).ok_or(ServerAnalysisError::UserOffsetNotFound)? as isize;
        log::debug!("CUser offset: {:x}", cuser_offset);
        Ok(cuser_offset)
}

pub(crate) fn analyze_call_dispatcher(fun: u64) -> Result<CallDispatcherData, ServerAnalysisError> {
    let pe = steam_client_pe().ok_or(ServerAnalysisError::CodeBounds)?;
    let code_bounds = client_code_bounds().ok_or(ServerAnalysisError::CodeBounds)?;
    if !code_bounds.contains(&fun) {
        return Err(ServerAnalysisError::CodeBounds);
    }

    let tier0_handle = "tier0_s.dll".get_handle().ok_or(ServerAnalysisError::IPCRecvStartNotFound)?;
    let ipcrecv_start = unsafe {
        GetProcAddress(HINSTANCE(tier0_handle as isize), PCSTR(b"ETW_Steamworks_IPCRecv_Start\0" as *const u8))
        .ok_or(ServerAnalysisError::IPCRecvStartNotFound)?
    } as u64;

    let mut results =  CallDispatcherData::default();

    let mut cfg = ControlFlowGraph::default();
    unsafe { cfg.build(fun, &code_bounds)? };

    let frame_reg = cfg.frame_register()
        .ok_or(ServerAnalysisError::NoFrameRegister(fun))?;

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
            let ip = *v.into.iter().next().ok_or(ServerAnalysisError::MissingName(icall))?;
            v = &cfg.graph[&ip];

            // Push instruction
            if v.instr.mnemonic() == Mnemonic::Push 
                && v.instr.op0_kind() == OpKind::Immediate32
                && let Some(str) = read_ascii_static_cstr(pe, v.instr.immediate32() as u64) 
            {
                str_refs.push_back(str);    
            }

            // IPCRecv_Start indirect call found
            if v.instr.is_call_near_indirect()
                && let Some(tgt) = v.instr.virtual_address(0, 0, |_,_,_| Some(0))
                && let Some(ptr) = unsafe { (tgt as *const u32).try_deref() }
                && ptr as u64 == ipcrecv_start
            {
                if str_refs.len() != 2 {
                    return Err(ServerAnalysisError::MissingName(icall))
                }
                if results.interface.is_empty() {
                    results.interface = str_refs[0];
                }
                else if results.interface != str_refs[0] {
                    return Err(ServerAnalysisError::ConflictingInterfaceNames(
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
            let ip = *v.into.iter().next().ok_or(ServerAnalysisError::MissingCallId(
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

/// Attempt to find a nested pointer to a Steam interface from CSteamEngine / CUser.
/// The first argument can be stored in 5 ways:
/// - Inline in the CSteamEngine (*often* virtual inheritance)
/// - Pointer in the CSteamEngine
/// - Inline in the CUser (virtual inheritance)
/// - Pointer in the CUser
/// - Pointer in the CUser with virtual inheritance
/// This argument is the "instance" of our global server interface.
/// We must go case by case and fetch it.
/// 
/// # Panics
/// if `param_ip` is not the IP of an instruction in `cfg`.
pub(crate) fn analyze_interface_ptr(cfg: &ControlFlowGraph, param_ip: u64) -> Result<(InterfaceBase, AsmNestedPtr), ServerAnalysisError> {
    let frame_reg = cfg.frame_register().ok_or(ServerAnalysisError::NoFrameRegister(cfg.root))?;
    let mut ptr = cfg.analyze_ptr(param_ip, 0, false, |ptr, ins| {
        if let PtrBase::Reg(r) = ptr.base {
            // Pointer to persistent var => CSteamEngine or CUser 
            if !r.is_volatile() {
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
    }).ok_or(ServerAnalysisError::PointerAnalysisFailed(param_ip))?;

    Ok((match ptr.base {
        PtrBase::Addr(_) => InterfaceBase::Static,
        PtrBase::Reg(r) => {
            if r == frame_reg && ptr.offsets.get(0) == Some(&INTERFACE_DISPATCH_STEAM_ENGINE_FRAME_OFFSET) {
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