#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include <tchar.h>
#include <cstdio>

#include "syscall.h"
#include "structs.h"

bool get_maximum_privileges();
bool unauthorized_access(ACCESS_MASK access_mask);

int main()
{
    if (!get_maximum_privileges())
        return 1;

    SIZE_T bufferSize = 0x10000;
    PVOID pHandleInfo = nullptr;
    const SIZE_T zero = 0;
    const ULONG currentProcessId = GetCurrentProcessId();

    NTSTATUS status = syscalls::nt_allocate_virtual_memory(
        GetCurrentProcess(),
        &pHandleInfo,
        0,
        (PULONG)&bufferSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status) || !pHandleInfo) {
        return 1;
    }

    while (true) {
        NTSTATUS status;
        do {
            status = syscalls::nt_query_system_information(16, pHandleInfo, bufferSize, nullptr);
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                bufferSize *= 2;

                PVOID newHandleInfo = nullptr;

                status = syscalls::nt_allocate_virtual_memory(
                    GetCurrentProcess(),
                    &newHandleInfo,
                    0,
                    (PULONG)&bufferSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                );

                syscalls::nt_free_virtual_memory(
                    GetCurrentProcess(),
                    &pHandleInfo,
                    &zero,
                    MEM_RELEASE
                );

                if (!NT_SUCCESS(status) || !newHandleInfo) {
                    return 1;
                }

                pHandleInfo = newHandleInfo;
            }
        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(status))
        {
            syscalls::nt_free_virtual_memory(
                GetCurrentProcess(),
                &pHandleInfo,
                &zero,
                MEM_RELEASE
            );
            return 1;
        }

        const auto handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(pHandleInfo);

        for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
            const SYSTEM_HANDLE& handle = handleInfo->Handles[i];
            if (handle.ProcessId == currentProcessId || !unauthorized_access(handle.GrantedAccess)) continue;

            const HANDLE hProcess = syscalls::nt_open_process(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                handle.ProcessId
            );
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) continue;

            HANDLE hDupHandle = nullptr;
            if (NT_SUCCESS(syscalls::nt_duplicate_object(
                hProcess,
                reinterpret_cast<HANDLE>(handle.Handle),
                GetCurrentProcess(),
                &hDupHandle,
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                0)))
            {
                if (GetProcessId(hDupHandle) == currentProcessId)
                {
                    TCHAR image_name[MAX_PATH];
                    DWORD nameLength = MAX_PATH;
                    if (!QueryFullProcessImageName(hProcess, 0, image_name, &nameLength))
                    {
                        _tcscpy_s(image_name, MAX_PATH, _T("UNKNOWN IMAGE NAME"));
                    }

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
                    else {
                        syscalls::nt_close(hDupHandle);
                    }
                }
                else {
                    syscalls::nt_close(hDupHandle);
                }
            }

            syscalls::nt_close(hProcess);
        }
    }

    syscalls::nt_free_virtual_memory(
        GetCurrentProcess(),
        &pHandleInfo,
        &zero,
        MEM_RELEASE
    );

    return 0;
}

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

bool get_maximum_privileges()
{
    HANDLE h_Process = GetCurrentProcess();
    HANDLE h_Token;
    DWORD dw_TokenLength;
    if (NT_SUCCESS(syscalls::nt_open_process_token(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h_Token)))
    {
        TOKEN_PRIVILEGES* privilages = new TOKEN_PRIVILEGES[100];
        if (GetTokenInformation(h_Token, TokenPrivileges, privilages, sizeof(TOKEN_PRIVILEGES) * 100, &dw_TokenLength))
        {
            for (int i = 0; i < privilages->PrivilegeCount; i++)
            {
                privilages->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
            }

            if (AdjustTokenPrivileges(h_Token, false, privilages, sizeof(TOKEN_PRIVILEGES) * 100, NULL, NULL))
            {
                delete[] privilages;
                return true;
            }
        }
        delete[] privilages;
    }
    return false;
}
