#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)

#include <type_traits>
#include <cstdint>

extern "C" void* syscall_stub();

namespace syscalls
{
    NTSTATUS nt_close(HANDLE handle);
    HANDLE nt_open_process(ACCESS_MASK access,
        DWORD pid);
    NTSTATUS nt_open_process_token(HANDLE ProcessHandle, ACCESS_MASK access, PHANDLE TokenHandle);
    NTSTATUS nt_query_system_information(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);
    NTSTATUS nt_duplicate_object(HANDLE SourceProcessHandle,
        HANDLE SourceHandle,
        HANDLE TargetProcessHandle,
        PHANDLE TargetHandle,
        ACCESS_MASK DesiredAccess,
        ULONG Attributes,
        ULONG Options);
    NTSTATUS nt_allocate_virtual_memory(
        _In_        HANDLE ProcessHandle,
        _Inout_     PVOID BaseAddress,
        _In_        ULONG ZeroBits,
        _Inout_     PULONG RegionSize,
        _In_        ULONG AllocationType,
        _In_        ULONG Protect);
    NTSTATUS nt_free_virtual_memory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType);
    NTSTATUS nt_adjust_privileges_token(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges, PTOKEN_PRIVILEGES NewState,
        ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);
}

namespace syscall
{
    template<typename T>
    using to_int64 = std::conditional_t < sizeof(T) < sizeof(int64_t), int64_t, T > ;

#pragma warning(push)
#pragma warning(disable : 4100)

    template<typename R, typename... Args>
    R syscall(int index, Args... args)
    {
        auto error = [](NTSTATUS status)
            {
                if constexpr (std::is_same_v<R, NTSTATUS>)
                    return status;
                else
                    return R();
            };

#ifdef USE32
        return error(STATUS_NOT_SUPPORTED);
#else
        static_assert(sizeof(R) <= sizeof(void*), "Return types larger than void* aren't supported");
        if (index == -1)
            return error(STATUS_INVALID_PARAMETER_1);

        // Cast types that otherwise will be only half-initialized
        auto pfn = reinterpret_cast<R(*)(int, size_t, to_int64<Args>...)>(syscall_stub);
        return pfn(index, sizeof...(Args), to_int64<Args>(args)...);
#endif
    }

    inline int get_index(const wchar_t* modName, const char* func)
    {
#ifdef USE32
        // Doesn't work for x86
        return -1;
#else
        const auto pfn = reinterpret_cast<const uint8_t*>(GetProcAddress(
            GetModuleHandleW(modName),
            func
        ));

        return pfn ? *reinterpret_cast<const int*>(pfn + 4) : -1;
#endif
    }

    inline int get_index(const char* func)
    {
        return get_index(L"ntdll.dll", func);
    }

    template<typename T, typename... Args>
    T syscall(const char* fn, Args&&... args)
    {
        return syscall<T>(get_index(fn), std::forward<Args>(args)...);
    }

#pragma warning(pop)
}