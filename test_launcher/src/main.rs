#![feature(absolute_path)]

use std::{error::Error, ffi::{CString, c_void}};

use windows::{core::PCSTR, Win32::{System::{Threading::{CreateRemoteThread, WaitForSingleObject}, Memory::MEM_RELEASE}, Foundation::WAIT_OBJECT_0}};
use windows::Win32::System::{Threading::{OpenProcess, PROCESS_ALL_ACCESS}, Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualFreeEx}, Diagnostics::Debug::WriteProcessMemory, LibraryLoader::{GetProcAddress, GetModuleHandleA}};

unsafe fn inject_dll(path: &str, pid: u32) -> Result<(), Box<dyn Error>> {
    let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

    let mem = VirtualAllocEx(handle, None, path.len() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if mem.is_null() {
        return Err("VirtualAllocEx failed".into());
    }

    let ret = || -> Result<(), Box<dyn Error>> {
        let cstr = CString::new(path)?;
        let mut n_written: usize = 0;
        if !WriteProcessMemory(handle, mem, cstr.as_ptr() as *const c_void, path.len() + 1, Some(&mut n_written as *mut usize)).as_bool() {
            return Err("WriteProcessMemory failed".into());
        }
        let llib = GetProcAddress(GetModuleHandleA(PCSTR(b"kernel32.dll\0" as *const u8))?, PCSTR(b"LoadLibraryA\0" as *const u8))
            .ok_or("GetProcAddress failed".to_owned())?;
        
        let mut t_id: u32 = 0;
        let t_handle = CreateRemoteThread(handle, None, 0, Some(std::mem::transmute(llib)), Some(mem), 0, Some(&mut t_id as *mut u32))?;

        if WaitForSingleObject(t_handle, 10000000) != WAIT_OBJECT_0 {
            return Err("Thread timed out".into());
        }

        Ok(())
    }();

    VirtualFreeEx(handle, mem, path.len() + 1, MEM_RELEASE);
    ret
}

#[cfg(target_arch = "x86_64")]
fn main() {
    // Currently, the test launcher only supports x86 to keep DLL injection simple.
    // TODO: Use Wow64EnumProcessModules or w/e for injection in x86 processes from x64. 
    println!("Please run the x86 version of this program, as DLL injection into a wow64 process from a non wow64 process is not supported.");
}

#[cfg(target_arch = "x86")]
fn main() -> Result<(), Box<dyn Error>> {
    use std::io::Read;
    use named_pipe::*;
    use steamworks::Client;
    use sysinfo::{SystemExt, ProcessExt, PidExt};

    // Init Steam
    let (client, _) = Client::init_app(480)?;

    let test_dll_path = std::path::absolute("./test_dll.dll")?;
    let system = sysinfo::System::new_all();
    let pid = system.processes()
        .iter()
        .find_map(|(&pid, proc)| if proc.name() == "steam.exe" { Some(pid) } else { None })
        .ok_or("steam is not running".to_owned())?;
    
    unsafe { inject_dll(test_dll_path.as_os_str().to_str().unwrap(), pid.as_u32())? };
    println!("test DLL injected");

    let mut ipc_server = PipeOptions::new("\\\\.\\pipe\\steamhook_test").single()?.wait()?;
    
    // Wait for signal from hook that steamhook is done
    let buf = &mut [0u8; 1];
    ipc_server.read_exact(buf)?;
    println!("hooks installed");
    
    let name = client.friends().name();
    println!("GetPersonaName (expecting your_new_name): {0}", name);
    assert_eq!(name, "your_new_name");
    
    let buf = &mut [0u8; 4];
    let (sid, _) = client.networking()
        .read_p2p_packet(buf)
        .ok_or("failed to read P2P packet".to_owned())?;

    println!("ReadP2PPacket (expecting [DE, AD, BE, EF] from 0xDEADBEEF): received {:X?} from user 0x{:X}", buf, sid.raw());
    assert_eq!(buf, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(sid.raw(), 0xDEADBEEF);

    println!("tests passed");
    Ok(())
}