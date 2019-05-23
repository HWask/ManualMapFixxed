#pragma once

#include <Windows.h>
#include <memory>
#include <map>
#include <algorithm>
#include <TlHelp32.h>
#include "Memory.h"
#include "Utils.h"

class Process
{
public:
	std::map<std::string, DWORD> mappedModules;
	std::map<std::string, DWORD> processModules;

	HANDLE _proc = 0;
	DWORD _pid = 0;
public:
	bool Attach(DWORD pid)
	{
		_pid = pid;
		_proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
		if (!_proc)
		{
			TRACE("OpenProcess failed");
			return false;
		}
		else
			return true;
	}

	bool IsAttached()
	{
		return _proc != 0;
	}

	void Detach()
	{
		CloseHandle(_proc);
	}

	Memory Alloc(size_t size)
	{
		auto mem = VirtualAllocEx(_proc, 0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mem)
		{
			TRACE("VirtualAllocEx failed");
			return Memory(0, 0);
		}
		else
		{
			Memory block(mem, _proc);
			block.bValid = true;
			return block;
		}
	}

	bool MemRead(void* source, void* dest, size_t size)
	{
		DWORD n;
		if (!ReadProcessMemory(_proc, source, dest, size, &n) || n != size)
		{
			TRACE("ReadProcessMemory failed");
			TRACE("Last Error: %d", GetLastError());
			return false;
		}
		else
			return true;
	}

	DWORD GetModuleBase(std::string name)
	{
		std::transform(name.begin(), name.end(), name.begin(), tolower);

		auto a = processModules.find(name);
		auto b = mappedModules.find(name);

		if (a != processModules.end())
			return a->second;

		if (b != mappedModules.end())
			return b->second;

		return 0;
	}

	bool FindModules()
	{
		processModules.clear();
		auto handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _pid);
		if (handle == INVALID_HANDLE_VALUE)
		{
			TRACE("CreateToolhelp32Snapshot failed");
			return false;
		}

		MODULEENTRY32 me;
		me.dwSize = sizeof(MODULEENTRY32);

		if (!Module32First(handle, &me))
		{
			TRACE("Module32First failed");
			CloseHandle(handle);
			return false;
		}

		std::string szModule(me.szModule);
		std::transform(szModule.begin(), szModule.end(), szModule.begin(), tolower);
		processModules.emplace(szModule, (DWORD)me.hModule);

		while (Module32Next(handle, &me))
		{
			std::string szModule(me.szModule);
			std::transform(szModule.begin(), szModule.end(), szModule.begin(), tolower);
			processModules.emplace(szModule, (DWORD)me.hModule);
		}

		CloseHandle(handle);
		return true;
	}
};