# Handle-Watcher
Handle Watcher is a C++ program designed to close process handles pointing to its process that have dangerous access rights. The purpose of this is to block memory from being accessed by tools like, but not limited to:
- Cheat Engine
- ProcessHacker / SystemInformer

# Quick explanation on how Handle Watcher works
The way it blocks memory from being accessed is simple: we use NtQuerySystemInformation to get information about all handles in the system. With this information, we can determine which process the handles are pointing to, which process owns the handle, the ACCESS_MASK of all handles, and more.

The first step we take is to make sure that the handle we’re inspecting does not belong to our process, and that the handle contains at least one of these access rights (you can add/remove access rights; I did it this way just because):
- PROCESS_ALL_ACCESS `CAN WRITE TO PROCESS MEMORY`
- PROCESS_VM_OPERATION `CAN WRITE TO PROCESS MEMORY`
- PROCESS_VM_WRITE `CAN WRITE TO PROCESS MEMORY`
- PROCESS_VM_READ
- PROCESS_DUP_HANDLE
- PROCESS_SET_INFORMATION
- PROCESS_SUSPEND_RESUME

If it doesn't, wel'll just continue with the next one.
```cpp
if (handle.ProcessId == currentProcessId || !unauthorized_access(handle.GrantedAccess)) continue;
```
unauthorized_access:
```cpp
bool unauthorized_access(const ACCESS_MASK access_mask)
{
    constexpr ACCESS_MASK UNAUTHORIZED_FLAGS = PROCESS_VM_WRITE |
        PROCESS_VM_READ |
        PROCESS_ALL_ACCESS |
        PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE |
        PROCESS_SET_INFORMATION |
        PROCESS_SUSPEND_RESUME;

    return (access_mask & UNAUTHORIZED_FLAGS) != 0;
}
```

If we determine that the handle should be subject to further inspection, we will open a handle to the process that owns the handle.
```cpp
const HANDLE hProcess = syscalls::nt_open_process(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
    handle.ProcessId
);
```
We take advantage of our `PROCESS_DUP_HANDLE` access to duplicate the handle that's pointing to our process.
```cpp
HANDLE hDupHandle = nullptr;
if (NT_SUCCESS(syscalls::nt_duplicate_object(
    hProcess,
    reinterpret_cast<HANDLE>(handle.Handle),
    GetCurrentProcess(),
    &hDupHandle,
    PROCESS_QUERY_LIMITED_INFORMATION,
    FALSE,
    0)))
```
We do this so we can finally know to which process the handle is pointing to. To do this, we simply use `GetProcessId` on `hDupHandle` and the result to our current process ID.
```cpp
if (GetProcessId(hDupHandle) == currentProcessId)
```
If we determine that the handle is pointing towards our process, we can then get the full image name of the process (`handle.ProcessId`) we're dealing with using `QueryFullProcessImageName`.
```cpp
TCHAR image_name[MAX_PATH];
DWORD nameLength = MAX_PATH;
if (!QueryFullProcessImageName(hProcess, 0, image_name, &nameLength))
{
    _tcscpy_s(image_name, MAX_PATH, _T("UNKNOWN IMAGE NAME"));
}
```
After doing this, to close the handle, we duplicate `handle.Handle` again, but this time using the `DUPLICATE_CLOSE_SOURCE` option. After doing this, we can simply run CloseHandle/NtClose on the handle.
```cpp
if (NT_SUCCESS(syscalls::nt_duplicate_object(
    hProcess,
    reinterpret_cast<HANDLE>(handle.Handle),
    GetCurrentProcess(),
    &hDupHandle,
    0,
    FALSE,
    DUPLICATE_CLOSE_SOURCE)))
{
    if (NT_SUCCESS(syscalls::nt_close(hDupHandle)))
    {
        printf("[closed handle] %s | ACCESS_MASK 0x%0X%\n", image_name, handle.GrantedAccess);
    }
    else {
        return 1;
    }
}
```
