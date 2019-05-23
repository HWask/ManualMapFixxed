#pragma once

#include "Process.h"
#include "PE.h"
#include "Utils.h"
#include "asmjit\x86\x86assembler.h"
#include <vector>

class MMap
{
public:
	Process _pe;
	Memory workerCode;

	std::vector<std::pair<DWORD, PE>> images;
public:
	MMap(Process& pe) : _pe(pe) {}

	void CreateRPCEnvironment()
	{
		workerCode = _pe.Alloc(100);
	}

	bool MapModule(std::string path)
	{
		if (!MapModuleInternal(path))
			return false;
		else
			TRACE("%s mapped correctly", path.c_str());

		for (auto mod : images)
			WipePEHeader(mod.first, mod.second.headerSize);

		TRACE("Wiped PE Headers");

		workerCode.Free();
		_pe.Detach();

		return true;
	}

	bool MapModule(void* buffer)
	{
		if (!MapModuleInternal(buffer))
			return false;
		else
			TRACE("File mapped correctly");

		for (auto mod : images)
			WipePEHeader(mod.first, mod.second.headerSize);

		TRACE("Wiped PE Headers");

		workerCode.Free();
		_pe.Detach();

		return true;
	}

	void WipePEHeader(DWORD base, DWORD headerSize)
	{
		DWORD n;
		BYTE* zeroBuff = new BYTE[headerSize];
		memset(zeroBuff, 0, headerSize);
		WriteProcessMemory(_pe._proc, (void*)base, zeroBuff, headerSize, &n);
		delete[] zeroBuff;
	}

	bool MapModuleInternal(void* buffer)
	{
		if (_pe.IsAttached())
		{
			PE file;
			if (file.Load(buffer))
			{
				TRACE("Loading file");
				if (file.Parse())
				{
					TRACE("Parsing PE file");
					Memory block = _pe.Alloc(file.imageSize);
					if (block.isValid())
					{
						//PE Header
						block.Write(file.pFileBase, 0, file.headerSize);
						//Sections
						CopySections(block, file);
						//Fix Relocs
						FixRelocs(block, file);
						//Fix Imports
						FixImports(block, file);
						//Run module initalizer
						RunModuleInitializer(block, file);

						images.push_back(std::make_pair((DWORD)block._base, file));

						TRACE("PE file loaded at: 0x%X", (DWORD)block._base);

						return true;
					}
				}
			}
		}

		return false;
	}

	bool MapModuleInternal(std::string path)
	{
		if (_pe.IsAttached())
		{
			TRACE("Mapping file %s", path.c_str());
			//module is already in the process
			if (_pe.GetModuleBase(Utils::GetFileNameWithExtensionFromPath(path)) != 0)
				return true;

			PE file;
			if (file.Load(path))
			{
				TRACE("Loading file %s", path.c_str());
				if (file.Parse())
				{
					TRACE("Parsing PE file");
					Memory block = _pe.Alloc(file.imageSize);
					TRACE("Allocated space");
					if (block.isValid())
					{
						TRACE("block is valid");
						//PE Header
						block.Write(file.pFileBase, 0, file.headerSize);
						TRACE("write pe header");
						//Sections
						CopySections(block, file);
						TRACE("copy sections");
						//Fix Relocs
						FixRelocs(block, file);
						TRACE("fix relocs");

						AddManualModule((DWORD)block._base, path);

						//Fix Imports
						FixImports(block, file);
						TRACE("imports fixed of %s", path.c_str());
						//Run module initalizer
						if(file.epRVA != 0)
							RunModuleInitializer(block, file);

						images.push_back(std::make_pair((DWORD)block._base, file));

						TRACE("PE file loaded at: 0x%X", (DWORD)block._base);

						return true;
					}
				}
			}
		}

		return false;
	}

	void AddManualModule(DWORD base, std::string path)
	{
		std::string mapped = Utils::GetFileNameWithExtensionFromPath(path);
		std::transform(mapped.begin(), mapped.end(), mapped.begin(), tolower);
		_pe.mappedModules.emplace(mapped, (DWORD)base);
	}

	void RemoveManualModule(std::string path)
	{
		std::string mapped = Utils::GetFileNameWithExtensionFromPath(path);
		std::transform(mapped.begin(), mapped.end(), mapped.begin(), tolower);

		auto it = _pe.mappedModules.find(mapped);
		if (it != _pe.mappedModules.end())
		{
			_pe.mappedModules.erase(it);
		}
	}

	void RunModuleInitializer(Memory& mem, PE file)
	{
		asmjit::JitRuntime jitruntime;
		asmjit::X86Assembler a(&jitruntime);

		//Prolog
		a.push(asmjit::x86::ebp);
		a.mov(asmjit::x86::ebp, asmjit::x86::esp);

		//call Entrypoint
		a.push(0);
		a.push(DLL_PROCESS_ATTACH);
		a.push((unsigned int)mem._base);
		a.mov(asmjit::x86::eax, (unsigned int)(file.epRVA + (DWORD)mem._base));
		a.call(asmjit::x86::eax);

		//Epilog
		a.mov(asmjit::x86::esp, asmjit::x86::ebp);
		a.pop(asmjit::x86::ebp);

		a.ret();

		void* code = a.make();
		auto size = a.getCodeSize();

		workerCode.Write(code, 0, size);
		auto thread = CreateRemoteThread(_pe._proc, 0, 0, (LPTHREAD_START_ROUTINE)workerCode._base, 0, 0, 0);
		if (!thread)
			TRACE("CreateRemoteThread failed");

		WaitForSingleObject(thread, INFINITE);
	}

	DWORD MapDependancy(std::string szDllName)
	{
		auto path = Utils::LookupDependancy(szDllName);
		if (path.empty()) //Error: Could not find dependancy
		{
			TRACE("Could not locate dependancy: %s", szDllName.c_str());
			return 0;
		}
		else
		{
			if (!MapModuleInternal(path)) //Error: Didnt succeed mapping dependancy
			{
				TRACE("Could not manual map: %s", szDllName.c_str());
				return 0;
			}
			else
			{
				//it needs to exist now since we just mapped it
				TRACE("Dependancy %s mapped correctly", szDllName.c_str());
				return _pe.GetModuleBase(szDllName);
			}
		}
	}

	void FixImports(Memory& target, PE& file)
	{
		auto imports = file.imports;

		for (auto keyVal : imports)
		{
			auto dllName = keyVal.first;
			auto hMod = _pe.GetModuleBase(dllName);
			TRACE("Import Dll: %s, 0x%X", dllName.c_str(), hMod);
			if (hMod == 0) //manual map this dependancy
			{
				TRACE("Mapping depedendancy: %s", dllName.c_str());
				hMod = MapDependancy(dllName);
				if (hMod == 0) //Error: Didnt succeed mapping dependancy
				{
					TRACE("Failed mapping dependancy");
					return;
				}
			}

			for (auto impData : keyVal.second)
			{
				if (impData.byOrdinal)
				{
					//Import by Ordinal
					TRACE("Import by Oridnal not handled");
				}
				else
				{
					auto functionAddr = GetExport(hMod, impData.name);
					if (!functionAddr)
						TRACE("Bad function address received");

					//TRACE("Fixxing import table 0x%X", impData.rva);
					target.Write((void*)impData.rva, functionAddr);
				}
			}
		}
	}

	DWORD GetExport(DWORD base, std::string fnName)
	{
		IMAGE_DOS_HEADER dos;
		IMAGE_NT_HEADERS32 nt;

		//TRACE("Read dos 2");
		_pe.MemRead((void*)base, &dos, sizeof(dos));
		//TRACE("Read nt 2");
		_pe.MemRead((void*)(base + dos.e_lfanew), &nt, sizeof(nt));

		auto expBase = (DWORD)base + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		BYTE* expTable = new BYTE[nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size];
		_pe.MemRead((void*)expBase, expTable, nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

		PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)expTable;

		auto offset = (DWORD)exportTable - nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		auto funcNames = (DWORD*)(exportTable->AddressOfNames + (DWORD)offset);
		auto functions = (DWORD*)(exportTable->AddressOfFunctions + (DWORD)offset);
		auto ordinals = (WORD*)(exportTable->AddressOfNameOrdinals + (DWORD)offset);

		for (int i = 0; i < exportTable->NumberOfNames; ++i)
		{
			std::string function((char*)(funcNames[i] + (DWORD)offset));
			auto ordinal = ordinals[i];

			if (!_stricmp(fnName.c_str(), function.c_str()))
			{
				auto funcAddress = functions[ordinal] + base;

				if (funcAddress >= expBase &&
					funcAddress <= expBase + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
				{
					//Forwarded Export
					char forwardStr[255] = { 0 };
					_pe.MemRead((void*)funcAddress, forwardStr, 255);
					std::string forwardedFunc((char*)forwardStr);
					std::string forwardDll = forwardedFunc.substr(0, forwardedFunc.find(".")) + ".dll";
					std::string forwardName = forwardedFunc.substr(forwardedFunc.find(".") + 1, std::string::npos);

					auto forwardBase = _pe.GetModuleBase(forwardDll);
					if (!forwardBase)
					{
						TRACE("forwardBase = 0, dll: %s", forwardDll.c_str());
						auto forwardDllBase = MapDependancy(forwardDll);
						TRACE("forwarded Dll mapped");
						return GetExport(forwardDllBase, forwardName);
					}
					else
					{
						if (forwardName.find("#") != std::string::npos)
						{
							TRACE("forwardImport by Ordinal");
						}
						else
						{
							delete[] expTable;
							return GetExport(forwardBase, forwardName);
						}
					}
				}
				else
				{
					delete[] expTable;
					return funcAddress;
				}
			}
		}

		delete[] expTable;
		return 0;
	}

	void FixRelocs(Memory& target, PE& file)
	{
		auto Delta = (DWORD)target._base - (DWORD)file.imgBase;

		auto start = file.GetDirectoryAddress(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		auto size = file.GetDirectorySize(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		auto end = start + size;

		if (!start || !size)
			return;

		auto relocData = (PE::RelocData*)start;
		while ((DWORD)relocData < end && relocData->BlockSize)
		{
			auto numRelocs = (relocData->BlockSize - 8) / 2;
			for (int i = 0; i < numRelocs; ++i)
			{
				auto offset = relocData->Item[i].Offset % 4096;
				auto type = relocData->Item[i].Type;

				if (type == IMAGE_REL_BASED_ABSOLUTE)
					continue;

				if (type == IMAGE_REL_BASED_HIGHLOW)
				{
					auto rva = relocData->PageRVA + offset;
					auto val = *(DWORD*)file.RVA2VA(rva) + Delta;
					target.Write((void*)rva, val);
				}
				else
					TRACE("Abnormal relocation type");
			}
			relocData = (PE::RelocData*)((DWORD)relocData + relocData->BlockSize);
		}
	}

	void CopySections(Memory& mem, PE& file)
	{
		for (int i = 0; i < file.sections.size(); ++i)
		{
			if (!(file.sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) && file.sections[i].SizeOfRawData != 0)
			{
				/*
				union {
				DWORD   PhysicalAddress;
				DWORD   VirtualSize;
				} Misc;
				DWORD   VirtualAddress;
				DWORD   SizeOfRawData;
				DWORD   PointerToRawData;
				*/
				TRACE("Writing section %d, VSize: %X, VA: %X, RawSize: %X ", i, file.sections[i].Misc.VirtualSize, 
					file.sections[i].VirtualAddress, file.sections[i].SizeOfRawData);

				auto pSource = file.RVA2VA(file.sections[i].VirtualAddress);
				mem.Write((void*)pSource, (void*)file.sections[i].VirtualAddress, file.sections[i].SizeOfRawData);
			}
		}
	}
};