#include <windows.h>
#include <ntstatus.h>
#include <winternl.h>
#include <tchar.h>
#include <cstdio>

#include "syscall.h"
#include "structs.h"

bool get_maximum_privileges();
bool is_access_dangerous(ACCESS_MASK access_mask);

const HANDLE current_process{ GetCurrentProcess() };

int main()
{
    if (!get_maximum_privileges())
        return 1;

    SIZE_T bufferSize{ 0x10000 };
    PVOID pHandleInfo{ NULL }; // This is where we'll initially store the information gotten from NtQuerySystemInformation.
    SIZE_T zero{ 0 };
    const ULONG current_pid{ GetCurrentProcessId() };

    // We allocate memory for pHandleInfo.
    NTSTATUS status{ syscalls::nt_allocate_virtual_memory(
        current_process,
        &pHandleInfo,
        0,
        (PULONG)&bufferSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    ) };

    if (!NT_SUCCESS(status) || !pHandleInfo) {
        return 1;
    }

    while (true) {
        do {
            // This is where we get the information from handles in the system.
            status = syscalls::nt_query_system_information(16, pHandleInfo, bufferSize, nullptr);
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                bufferSize *= 2;

                PVOID _pHandleInfo{ nullptr };

                syscalls::nt_allocate_virtual_memory(
                    current_process,
                    &_pHandleInfo,
                    0,
                    (PULONG)&bufferSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                );

                syscalls::nt_free_virtual_memory(
                    current_process,
                    &pHandleInfo,
                    &zero,
                    MEM_RELEASE
                );

                if (!_pHandleInfo) {
                    return 1;
                }

                pHandleInfo = _pHandleInfo;
            }
        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(status))
        {
            syscalls::nt_free_virtual_memory(
                current_process,
                &pHandleInfo,
                &zero,
                MEM_RELEASE
            );
            return 1;
        }

        const auto handleInfo{ reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(pHandleInfo) };

        for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
            const SYSTEM_HANDLE& handle{ handleInfo->Handles[i] };
            // handle.ProcessId == current_pid checks that the handle doesn't belong to our process.
            // !is_access_dangerous(handle.GrantedAccess) checks handle.GrantedAccess and verifies if it has dangerous access.
            if (handle.ProcessId == current_pid || !is_access_dangerous(handle.GrantedAccess)) continue;

            // If the condition above isn't met, we create a handle to the process that owns the handle.
            // We do this so we can duplicate the handle that's pointing to us and to get information from the process.
            const HANDLE hProc{ syscalls::nt_open_process(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                handle.ProcessId
            ) };

            if (!hProc || hProc == INVALID_HANDLE_VALUE) {
                CloseHandle(hProc);
                continue;
            }

            HANDLE dup_handle = nullptr;
            if (NT_SUCCESS(syscalls::nt_duplicate_object(
                hProc,
                reinterpret_cast<HANDLE>(handle.Handle),
                current_process,
                &dup_handle,
                PROCESS_QUERY_LIMITED_INFORMATION, /* We use this so in case handle.Handle doesn't have enough access
                                                    * to let us run GetProcessId on dup_handle, we can still do it. */
                FALSE,
                0)))
            {
                if (GetProcessId(dup_handle) == current_pid) /* We check if the handle is pointing to us because that way we
                                                              * know that we should terminate the handle. */
                {
                    TCHAR image_name[MAX_PATH];
                    DWORD nameLength{ MAX_PATH };
                    if (!QueryFullProcessImageName(hProc, 0, image_name, &nameLength))
                    {
                        /* If QueryFullProcessImageName fails, we'll just set image_name to UNKNOWN IMAGE NAME.
                         * We do this to have something to print later.
                         * It shouldn't fail because hProc has PROCESS_QUERY_LIMITED_INFORMATION access. */
                        _tcscpy_s(image_name, MAX_PATH, _T("UNKNOWN IMAGE NAME"));
                    }

                    /* After making sure the handle is pointing to our process and getting the image name of the process,
                     * we will duplicate the handle again, however this time we'll use the option DUPLICATE_CLOSE_SOURCE.
                     * We do this because this option allows us to terminate the actual handle. */
                    if (NT_SUCCESS(syscalls::nt_duplicate_object(
                        hProc,
                        reinterpret_cast<HANDLE>(handle.Handle),
                        current_process,
                        &dup_handle,
                        0,
                        FALSE,
                        DUPLICATE_CLOSE_SOURCE)))
                    {
                        if (NT_SUCCESS(syscalls::nt_close(dup_handle))) /* This line gets the job done. We've now terminated
                                                                         * the handle. */
                        {
                            printf("[closed handle] %s | ACCESS_MASK 0x%0X%\n", image_name, handle.GrantedAccess);
                        }
                        else {
                            return 1;
                        }
                    }
                    else {
                        syscalls::nt_close(dup_handle);
                    }
                }
                else {
                    syscalls::nt_close(dup_handle);
                }
            }

            syscalls::nt_close(hProc);
        }
    }

    syscalls::nt_free_virtual_memory(
        current_process,
        &pHandleInfo,
        &zero,
        MEM_RELEASE
    );

    return 0;
}

bool is_access_dangerous(const ACCESS_MASK access_mask)
{
    constexpr ACCESS_MASK UNAUTHORIZED_FLAGS{ PROCESS_VM_WRITE |
        PROCESS_VM_READ |
        PROCESS_ALL_ACCESS |
        PROCESS_VM_OPERATION |
        PROCESS_DUP_HANDLE |
        PROCESS_SET_INFORMATION |
        PROCESS_SUSPEND_RESUME };

    return (access_mask & UNAUTHORIZED_FLAGS) != 0;
}

bool get_maximum_privileges()
{
    HANDLE h_Token{ };
    DWORD dw_TokenLength{ };
    if (NT_SUCCESS(syscalls::nt_open_process_token(current_process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h_Token)))
    {
        TOKEN_PRIVILEGES* privilages{ new TOKEN_PRIVILEGES[100] };
        if (GetTokenInformation(h_Token, TokenPrivileges, privilages, sizeof(TOKEN_PRIVILEGES) * 100, &dw_TokenLength))
        {
            for (int i = 0; i < privilages->PrivilegeCount; i++)
            {
                privilages->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
            }

            if (NT_SUCCESS(syscalls::nt_adjust_privileges_token(h_Token, false, privilages, sizeof(TOKEN_PRIVILEGES) * 100, NULL, NULL)))
            {
                delete[] privilages;
                return true;
            }
        }
        delete[] privilages;
    }
    return false;
}
