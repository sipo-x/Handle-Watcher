#include "syscall.h"
#include <cstdio>

NTSTATUS syscalls::nt_close(HANDLE handle)
{
    NTSTATUS status = syscall::syscall<NTSTATUS>("NtClose", handle);

    return status;
}

HANDLE syscalls::nt_open_process(ACCESS_MASK access, DWORD pid) 
{
	CLIENT_ID client_id{};
	client_id.UniqueProcess = (HANDLE)pid;

	OBJECT_ATTRIBUTES objAttr{};

	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	HANDLE handle{ NULL };

	NTSTATUS status = syscall::syscall<NTSTATUS>("NtOpenProcess", &handle, access, objAttr, client_id);
	if (NT_SUCCESS(status))
		return handle;

	return NULL;
}

NTSTATUS syscalls::nt_open_process_token(HANDLE ProcessHandle, ACCESS_MASK access, PHANDLE TokenHandle)
{
    NTSTATUS status = syscall::syscall<NTSTATUS>("NtOpenProcessToken", ProcessHandle, access, TokenHandle);

    return status;
}

NTSTATUS syscalls::nt_query_system_information(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    NTSTATUS status = syscall::syscall<NTSTATUS>(
        "NtQuerySystemInformation",
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    return status;
}

NTSTATUS syscalls::nt_duplicate_object(HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
)
{
    NTSTATUS status = syscall::syscall<NTSTATUS>(
        "NtDuplicateObject",
        SourceProcessHandle,
        SourceHandle,
        TargetProcessHandle,
        TargetHandle,
        DesiredAccess,
        Attributes,
        Options
    );

    return status;
}

NTSTATUS syscalls::nt_allocate_virtual_memory(
    _In_        HANDLE ProcessHandle,
    _Inout_     PVOID BaseAddress,
    _In_        ULONG ZeroBits,
    _Inout_     PULONG RegionSize,
    _In_        ULONG AllocationType,
    _In_        ULONG Protect
)
{
    NTSTATUS status = syscall::syscall<NTSTATUS>(
        "NtAllocateVirtualMemory",
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    );

    return status;
}

NTSTATUS syscalls::nt_free_virtual_memory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
)
{
    NTSTATUS status = syscall::syscall<NTSTATUS>("NtFreeVirtualMemory",
        ProcessHandle,
        BaseAddress,
        RegionSize,
        FreeType
    );

    return status;
}