#include "mapper.h"

namespace mapper
{
	PBYTE inject(std::string target_dll, std::string target_exe)
	{
		xigndriver::initialize();
		printf("Getting target PID...\n");

		auto target_id = process::get_process_id(target_exe);
		while (!target_id)
			target_id = process::get_process_id(target_exe);

		Sleep(500);

		printf("%s: %d\n", target_exe.c_str(), target_id);
		auto target_handle = xigndriver::open_process(target_exe);/*OpenProcess(PROCESS_ALL_ACCESS, NULL, target_id);//*/

		if (target_handle)
		{
			auto imported_modules = process::get_imported_modules(target_id);
			return inject_ex(target_handle, target_dll, imported_modules);
		}
		else
		{
			printf("Unable to open target handle: %d\n", GetLastError());
			return NULL;
		}

		return NULL;

	}

	PBYTE inject_ex(HANDLE target_handle, std::string dll_name, std::map<std::string, uint32_t> &imported_modules)
	{
		printf("Mapping %s into target\n", dll_name.c_str());

		auto local_image = utils::read_file(dll_name);

		auto dosHeader = (PIMAGE_DOS_HEADER)local_image;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((uint32_t)local_image + dosHeader->e_lfanew);
		auto sectHeader = (PIMAGE_SECTION_HEADER)(&ntHeaders->OptionalHeader + 1);

		auto target_image = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		auto target_mem = VirtualAllocEx(target_handle, NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (target_image && target_mem)
		{
			mapper::copy_sections(target_handle, local_image, target_image);

			mapper::relocate_base(target_image, target_mem);

			mapper::fix_imports(target_handle, target_image, imported_modules);

			if (!WriteProcessMemory(target_handle, target_mem, target_image, ntHeaders->OptionalHeader.SizeOfImage, NULL))
			{
				printf("Unable to write relocated image to target image: %d\n", GetLastError());
				VirtualFree(target_image, NULL, MEM_RELEASE);
				VirtualFree(local_image, NULL, MEM_RELEASE);
				VirtualFreeEx(target_handle, target_mem, NULL, MEM_RELEASE);
				return 0;
			}
			uint32_t size = abs((int)((uint32_t)mapper::LoadDll - (uint32_t)mapper::LoadDllEnd));

			if (process::inject_function(target_handle, size, (LPVOID)mapper::LoadDll, (LPVOID)target_mem))
			{
				printf("Manual Mapped %s\n", dll_name.c_str());

				char *tmp = (char *)VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				tmp = PathFindFileName(dll_name.c_str());
				imported_modules.insert(std::make_pair(tmp, (uint32_t)target_mem));
				return (PBYTE)target_mem;
			}
			else
			{
				printf("Unable to inject loader into target memory: %d\n", GetLastError());
				CloseHandle(target_handle);
				VirtualFree(target_image, NULL, MEM_RELEASE);
				VirtualFree(target_mem, NULL, MEM_RELEASE);
				VirtualFree(local_image, NULL, MEM_RELEASE);
				return NULL;
			}
		}
		else
		{
			printf("Unable to allocate target memory: %d\n", GetLastError());
			CloseHandle(target_handle);
			if (target_image) VirtualFree(target_image, NULL, MEM_RELEASE);
			VirtualFree(local_image, NULL, MEM_RELEASE);
			return NULL;
		}
	}

	void copy_sections(HANDLE target_handle, LPVOID local_image, LPVOID target_image)
	{
		auto dos_header = (PIMAGE_DOS_HEADER)local_image;
		auto nt_headers = (PIMAGE_NT_HEADERS32)((uint32_t)local_image + dos_header->e_lfanew);
		auto sect_header = (PIMAGE_SECTION_HEADER)(&nt_headers->OptionalHeader + 1);

		memcpy(target_image, local_image, nt_headers->OptionalHeader.SizeOfHeaders);
		for (auto count = 0; count < nt_headers->FileHeader.NumberOfSections; count++)
		{

			memcpy((PBYTE)target_image + sect_header[count].VirtualAddress, (PBYTE)local_image + sect_header[count].PointerToRawData, sect_header[count].SizeOfRawData);
		}
	}

	void relocate_base(LPVOID target_image, LPVOID target_mem)
	{
		auto nt_headers = (PIMAGE_NT_HEADERS32)((LPBYTE)target_image + ((PIMAGE_DOS_HEADER)target_image)->e_lfanew);
		auto pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)target_image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		auto delta = (DWORD)((LPBYTE)target_mem - nt_headers->OptionalHeader.ImageBase);
		while (pIBR->VirtualAddress)
		{
			if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
			{
				auto count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto list = (PWORD)(pIBR + 1);

				for (auto i = 0; i < count; i++)
				{
					if (list[i])
					{
						auto ptr = (PDWORD)((LPBYTE)target_image + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
						*ptr += delta;
					}
				}
			}

			pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
		}

		/*
		auto nt_headers = (PIMAGE_NT_HEADERS32)((LPBYTE)target_image + ((PIMAGE_DOS_HEADER)target_image)->e_lfanew);

		auto base_reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)target_image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		for (; base_reloc->VirtualAddress; base_reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)base_reloc + base_reloc->SizeOfBlock))
		{
			auto first_reloc = (PWORD)((PBYTE)base_reloc + sizeof(IMAGE_BASE_RELOCATION));
			for (auto x = 0; x < (base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); x++)
			{
				auto reloc_address = (PBYTE)target_image + base_reloc->VirtualAddress + (first_reloc[x] & 0xFFF);
				switch (*first_reloc >> 12)
				{

				case IMAGE_REL_BASED_HIGHLOW:
					*reloc_address += (uint32_t)((PBYTE)target_mem - nt_headers->OptionalHeader.ImageBase);
					break;

				case IMAGE_REL_BASED_DIR64:
					*(uint64_t *)reloc_address += ((uint64_t)target_mem - nt_headers->OptionalHeader.ImageBase);
					break;

				default:
					printf("Didnt catch relocation: %d\n", *first_reloc >> 12);
					break;
				}
			}
		}*/
	}

	void fix_imports(HANDLE target_handle, LPVOID target_image, std::map<std::string, uint32_t> &imported_modules)
	{
		auto nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)target_image + ((PIMAGE_DOS_HEADER)target_image)->e_lfanew);
		auto import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)target_image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		char *module_name = (char *)VirtualAlloc(NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		for (; import_desc->Name; import_desc++)
		{
			ZeroMemory(module_name, MAX_PATH);
			HMODULE loadee_base = LoadLibrary((LPCSTR)((uint32_t)target_image + import_desc->Name));
			GetModuleFileNameA(loadee_base, module_name, MAX_PATH);

			auto base_addr = mapper::contains(imported_modules, module_name);
			if(!base_addr)
				base_addr = (uint32_t)mapper::inject_ex(target_handle, module_name, imported_modules);

			auto _thunk_data = (PIMAGE_THUNK_DATA)((uint32_t)target_image + import_desc->FirstThunk);
			auto thunk_data = (PIMAGE_THUNK_DATA)((uint32_t)target_image + import_desc->OriginalFirstThunk);

			for(; thunk_data->u1.Function != NULL; thunk_data++, _thunk_data++)
			{
				auto import_name = (PIMAGE_IMPORT_BY_NAME)((uint32_t)target_image + thunk_data->u1.AddressOfData);
				_thunk_data->u1.Function = (uint32_t)GetProcAddress(loadee_base, import_name->Name) + (imported_modules.find(module_name)->second - (uint32_t)GetModuleHandle(module_name));
			}
		}
	}

	uint32_t contains(std::map<std::string, uint32_t> imported_modules, LPCSTR module_name)
	{

		std::map<std::string, uint32_t>::iterator it = imported_modules.begin();
		while (it != imported_modules.end())
		{
			if (!_stricmp(it->first.c_str(), module_name))
				return it->second;
			it++;
		}

		return NULL;
	}


	uint32_t LoadDll(LPVOID targetImage)
	{
		
		typedef BOOL(WINAPI *DllMainStub)(HINSTANCE, DWORD, LPVOID);
		auto dosHeader = (PIMAGE_DOS_HEADER)targetImage;
		auto ntHeaders = (PIMAGE_NT_HEADERS32)((uint32_t)targetImage + dosHeader->e_lfanew);

		if (ntHeaders->OptionalHeader.AddressOfEntryPoint)
		{
			auto oep = (DllMainStub)((PBYTE)targetImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);		
			oep((HMODULE)targetImage, DLL_PROCESS_ATTACH, NULL);

		}
		return 1;
	}

	void LoadDllEnd() {}
}