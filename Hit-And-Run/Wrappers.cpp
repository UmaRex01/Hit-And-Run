#include "Wrappers.h"
#include "Utils.h"
#include <stdio.h>
#include <windows.h>

#define ZwAllocateVirtualMemoryHash		0xD33D4AED
#define ZwWriteVirtualMemoryHash		0xC5D0A4C2
#define ZwProtectVirtualMemoryHash		0xBC3F4D89
#define ZwCreateThreadExHash			0xCD1DF775

static PVOID EXCP_ADDR = NULL;
static PVOID SYSC_ADDR = NULL;
static DWORD SSN = 0;

static DWORD STACKS_ARGS_NUMBER;
static PCONTEXT SAVED_CONTEXT = NULL;
static PVOID REDIRECT_TO_ADDR = NULL;

//Hardware breakpoint related from https://gist.github.com/CCob/fe3b63d80890fafeca982f76c8a3efdf
unsigned long long setBits(unsigned long long dw, int lowBit, int bits, unsigned long long newValue)
{
	unsigned long long mask = (1UL << bits) - 1UL;
	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
	return dw;
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

extern "C" EXCEPTION_DISPOSITION __cdecl __C_specific_handler(struct _EXCEPTION_RECORD* ExceptionRecord, void* Frame, struct _CONTEXT* ContextRecord, struct _DISPATCHER_CONTEXT* Dispatch)
{
	// FIRST HIT - at EXCP_ADDR (ntdll function first instruction)
	if (ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
		ExceptionRecord->ExceptionAddress == EXCP_ADDR)
	{
		ClearBreakpoint(ContextRecord, 0);

		// Save context for later restoration
		SAVED_CONTEXT = (PCONTEXT)HeapAlloc(GetProcessHeap(), 0, sizeof(CONTEXT));
		memcpy_s(SAVED_CONTEXT, sizeof(CONTEXT), ContextRecord, sizeof(CONTEXT));

		// Redirect execution to the custom function
		ContextRecord->Rip = (DWORD64)REDIRECT_TO_ADDR;
		return ExceptionContinueExecution;
	}

	// SECOND HIT - at SYSC_ADDR (syscall address)
	if (ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
		ExceptionRecord->ExceptionAddress == SYSC_ADDR)
	{
		// Restore original stack arguments
		ContextRecord->Rcx = SAVED_CONTEXT->Rcx;
		ContextRecord->Rdx = SAVED_CONTEXT->Rdx;
		ContextRecord->R8 = SAVED_CONTEXT->R8;
		ContextRecord->R9 = SAVED_CONTEXT->R9;

		//printf("\n\n --debug begin-- \n\n");
		DWORD k = 0x1;
		// Restore stack values for arguments
		while (STACKS_ARGS_NUMBER > 0)
		{
			DWORD offset = 0x8 * (0x4 + k);
			//printf("address on stack: %p - %p\n", exception->ContextRecord->Rsp + offset, SAVED_CONTEXT->Rsp + offset);
			//printf("values: %p - %p\n", *(ULONG64*)(exception->ContextRecord->Rsp + offset), *(ULONG64*)(SAVED_CONTEXT->Rsp + offset));
			*(ULONG64*)(ContextRecord->Rsp + offset) = *(ULONG64*)(SAVED_CONTEXT->Rsp + offset);
			//printf("new values: %p - %p\n\n", *(ULONG64*)(exception->ContextRecord->Rsp + offset), *(ULONG64*)(SAVED_CONTEXT->Rsp + offset));
			STACKS_ARGS_NUMBER--;
			k += 0x1;
		}
		//printf("\n\n --debug end-- \n\n");

		ContextRecord->R10 = ContextRecord->Rcx;

		ClearBreakpoint(ContextRecord, 1);
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, SAVED_CONTEXT);

		return ExceptionContinueExecution;
	}

	return ExceptionContinueSearch;
}

static BOOL PrepareAndSetBreakpoint(DWORD functionHash)
{
	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext((HANDLE)-2, &threadContext))
		return FALSE;

	// Resolve addresses for function and syscall

	EXCP_ADDR = SW3_GetFunctionVAddress(functionHash);
	if (EXCP_ADDR == NULL)
		return FALSE;

	SYSC_ADDR = SW3_GetSyscallAddress(functionHash);
	if (SYSC_ADDR == NULL)
		return FALSE;

	SSN = SW3_GetSyscallNumber(functionHash);
	if (SSN == 0)
		return FALSE;

	// Enable breakpoints at the function and syscall addresses

	EnableBreakpoint(&threadContext, EXCP_ADDR, 0);
	EnableBreakpoint(&threadContext, SYSC_ADDR, 1);

	SetThreadContext((HANDLE)-2, &threadContext);

	return TRUE;
}

// Initialize function by populating syscall list and setting up exception handler
BOOL Init()
{
	if (!SW3_PopulateSyscallList())
		return FALSE;

	return TRUE;
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

NTSTATUS CallNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	REDIRECT_TO_ADDR = &DummyVirtualAllocEx;
	STACKS_ARGS_NUMBER = 2;
	if (!PrepareAndSetBreakpoint(ZwAllocateVirtualMemoryHash))
		return NULL;
	return ((NtAllocateVirtualMemory)EXCP_ADDR)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS CallNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten)
{
	REDIRECT_TO_ADDR = &DummyWriteProcessMemory;
	STACKS_ARGS_NUMBER = 1;
	if (!PrepareAndSetBreakpoint(ZwWriteVirtualMemoryHash))
		return FALSE;
	return ((NtWriteVirtualMemory)EXCP_ADDR)(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS CallNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
	REDIRECT_TO_ADDR = &DummyVirtualProtect;
	STACKS_ARGS_NUMBER = 1;
	if (!PrepareAndSetBreakpoint(ZwProtectVirtualMemoryHash))
		return FALSE;
	return ((NtProtectVirtualMemory)EXCP_ADDR)(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS CallCreateRemoteThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine,
	PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList)
{
	REDIRECT_TO_ADDR = &DummyCreateRemoteThread;
	STACKS_ARGS_NUMBER = 7;
	if (!PrepareAndSetBreakpoint(ZwCreateThreadExHash))
		return NULL;
	return ((NtCreateThreadEx)EXCP_ADDR)(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine,
		Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}
