#include "HandleHijacker.h"

//base on https://github.com/SafeBreach-Labs/PoolParty/blob/main/PoolParty/HandleHijacker.cpp

HANDLE HijackProcessHandle(HANDLE hProcess, DWORD dwDesiredAccess)
{
    HMODULE hNtdll;
    FN_NtQueryInformationProcess _NtQueryInformationProcess;
    FN_NtQueryObject _NtQueryObject;

    ULONG size = 1 << 10;
    std::unique_ptr<BYTE[]> buffer;


    hNtdll = LoadLibraryA("Ntdll.dll");
    if (hNtdll == nullptr) {
        return INVALID_HANDLE_VALUE;
    }

    _NtQueryInformationProcess = (FN_NtQueryInformationProcess)GetProcAddress(hNtdll,"NtQueryInformationProcess");
    _NtQueryObject = (FN_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
    if (_NtQueryInformationProcess == nullptr || _NtQueryObject == nullptr) {
        FreeLibrary(hNtdll);
        return INVALID_HANDLE_VALUE;
    }

    for (;;) {
        buffer = std::make_unique<BYTE[]>(size);
        auto status = _NtQueryInformationProcess(hProcess, (PROCESS_INFORMATION_CLASS)ProcessHandleInformation,
            buffer.get(), size, &size);
        if (NT_SUCCESS(status))
            break;
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            size += 1 << 10;
            continue;
        }
    }

    auto info = reinterpret_cast<PROCESS_HANDLE_SNAPSHOT_INFORMATION*>(buffer.get());
    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
        HANDLE h = info->Handles[i].HandleValue;
        HANDLE hTarget;
        if (!::DuplicateHandle(hProcess, h, ::GetCurrentProcess(), &hTarget,
            0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;

        PPUBLIC_OBJECT_TYPE_INFORMATION pobj_type_info;
        BYTE buffer[512] = { 0 };

        auto status = _NtQueryObject(hTarget, ObjectTypeInformation,
            &buffer, 512, nullptr);

        if (wcscmp(((PPUBLIC_OBJECT_TYPE_INFORMATION)buffer)->TypeName.Buffer,L"IoCompletion") == 0) {
            return hTarget;
        }
        else
        {
            CloseHandle(hTarget);
        }
    }
    return INVALID_HANDLE_VALUE;
}
