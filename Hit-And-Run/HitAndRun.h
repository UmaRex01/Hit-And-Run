#pragma once
#include <Windows.h>
#include "Native.h"

#ifdef _DEBUG
#define print_debug(...) printf(__VA_ARGS__)
#else
#define print_debug(...) do{} while(0)
#endif

typedef struct _HIR_CTX {
	PVOID pExceptionAddress;
	PVOID pSyscallAddress;
	DWORD dwSSN;
	DWORD dwStacksArgsNumber;
	PCONTEXT pSavedContext;
	PVOID pRedirectFunction;
} HIR_CTX, * PHIR_CTX;

//
// 
// DEFINE HERE YOUR WRAPPER FUNCTIONS HERE
//
//

#define ZwAllocateVirtualMemoryHash		0xD33D4AED
#define ZwWriteVirtualMemoryHash		0xC5D0A4C2
#define ZwProtectVirtualMemoryHash		0xBC3F4D89
#define ZwCreateThreadExHash			0xCD1DF775

NTSTATUS CallNtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

NTSTATUS CallNtWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten
);

NTSTATUS CallNtProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect
);

NTSTATUS CallCreateRemoteThread(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartRoutine,
	PVOID Argument,
	ULONG CreateFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PPS_ATTRIBUTE_LIST AttributeList
);

//
// 
// The following code is a simplified version of SysWhisper3's original functions
// https://github.com/klezVirus/SysWhispers3/blob/master/data/base.h
//
//

#define SW3_MAX_ENTRIES 600
#define SW3_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _SW3_SYSCALL_ENTRY
{
	DWORD Hash;
	DWORD Address;
	PVOID VAddress;
	PVOID SyscallAddress;
} SW3_SYSCALL_ENTRY, * PSW3_SYSCALL_ENTRY;

typedef struct _SW3_SYSCALL_LIST
{
	DWORD Count;
	SW3_SYSCALL_ENTRY Entries[SW3_MAX_ENTRIES];
} SW3_SYSCALL_LIST, * PSW3_SYSCALL_LIST;

typedef struct _SW3_PEB_LDR_DATA
{
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW3_PEB_LDR_DATA, * PSW3_PEB_LDR_DATA;

typedef struct _SW3_LDR_DATA_TABLE_ENTRY
{
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW3_LDR_DATA_TABLE_ENTRY, * PSW3_LDR_DATA_TABLE_ENTRY;

typedef struct _SW3_PEB
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW3_PEB_LDR_DATA Ldr;
} SW3_PEB, * PSW3_PEB;

BOOL SW3_PopulateSyscallList();
DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
PVOID SW3_GetFunctionVAddress(DWORD FunctionHash);