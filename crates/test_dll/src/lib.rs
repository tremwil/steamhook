
use std::error::Error;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::LibraryLoader::{DisableThreadLibraryCalls, FreeLibraryAndExitThread};
use windows::Win32::System::Console::{AllocConsole, GetConsoleWindow};

use ::steamhook::*;
use ::steamhook::singleton::RwSingleton;

unsafe fn setup_console() -> Result<(), Box<dyn Error>> {
    if GetConsoleWindow().0 == 0 && !AllocConsole().as_bool() {
        return Err("Failed to allocate console".into());
    }
    std::process::Command::new("CMD").args(["/C", "CLS"]).status()?;
    Ok(())
}

fn steamhook_test() -> Result<(), Box<dyn Error>> {
    unsafe { setup_console()?; }
    simple_logger::init_with_level(log::Level::Debug)?;

    SteamHook::instance_mut().init()?;
    for (name, int) in SteamHook::instance().interfaces() {
        println!("{} -> {:?}", name, int.instance())
    }
    Ok(())
}

#[allow(non_snake_case)]
#[allow(unused_variables)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(hInstDll: HINSTANCE, fdwReason: u32, lpvReserved: *const()) -> i32 {
    if fdwReason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hInstDll);
        let _ = std::thread::spawn(move || {
            let exit_code = match std::panic::catch_unwind(steamhook_test) {
                Err(e) => {
                    println!("erp2p_proxy panicked in steamhook_test: {:#?}", e);
                    1
                }
                Ok(Err(e)) => {
                    println!("Encountered an error during steamhook_test: {:#?}", e);
                    1
                }
                Ok(_) => 0,
            };
            memory_utils::clean_up_veh();
            FreeLibraryAndExitThread(hInstDll, exit_code);
        });
    }
    1
}