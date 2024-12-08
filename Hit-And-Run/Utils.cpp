#include "Utils.h"
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>

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

DWORD FindProcessByName(const TCHAR* procName)
{
	HANDLE hSnapshot;
	DWORD dwProcId = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_tcsicmp(pe32.szExeFile, procName) == 0) {
				dwProcId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return dwProcId;
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