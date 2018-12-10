#include "mapper.h"

namespace mapper
{
	std::vector<module_info> module_list;
	LPCSTR vuln_module = "kernel32.dll", vuln_function = "TlsSetValue";

	PVOID inject(std::string target_proc, std::string dll)
	{
		xigndriver::initialize();

		auto target_pid = process::get_process_id(target_proc);
		while (!target_pid)
			target_pid = process::get_process_id(target_proc);

		auto target_handle = xigndriver::open_process(target_proc);
		printf("%x\n", target_handle);
		
		if (target_handle)
		{
			auto image_base = inject_ex(target_handle, target_proc, dll);
			if (image_base)
				return image_base;
			else
				printf("Error injecting %s into %s", dll.c_str(), target_proc.c_str());
		}
		else
		{
			printf("Error %X acquiring handle to %X-%s\n", GetLastError(), target_pid, target_proc.c_str());
		}

		return NULL;
	}

	PVOID inject_ex(HANDLE target_handle, std::string target_proc, std::string dll)
	{
		auto local_image = utils::read_file(dll.c_str());

		auto dosHeader = (PIMAGE_DOS_HEADER)local_image;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((uint64_t)local_image + dosHeader->e_lfanew);
		auto sectHeader = (PIMAGE_SECTION_HEADER)(&ntHeaders->OptionalHeader + 1);

		auto fixed_image = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		auto target_mem = VirtualAllocEx(target_handle, NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (fixed_image && target_mem)
		{
			mapper::copy_sections(local_image, fixed_image);
			mapper::relocate_base(fixed_image, target_mem);
			mapper::fix_imports(target_handle, fixed_image, target_proc);

			if (!WriteProcessMemory(target_handle, target_mem, fixed_image, ntHeaders->OptionalHeader.SizeOfImage, NULL))
			{
				printf("Unable to write relocated image to target image: %X\n", GetLastError());
				VirtualFree(fixed_image, NULL, MEM_RELEASE);
				VirtualFree(local_image, NULL, MEM_RELEASE);
				VirtualFreeEx(target_handle, target_mem, NULL, MEM_RELEASE);
				return 0;
			}

			mapper::call_entrypoint(target_handle, target_mem, fixed_image);

			return target_mem;
		}
		else
		{
			printf("Unable to allocate memory for image (local: %X, remote: %X)\n", fixed_image, target_mem);
		}

		return NULL;

	}

	void copy_sections(LPVOID local_image, LPVOID fixed_image)
	{
		auto dos_header = (PIMAGE_DOS_HEADER)local_image;
		auto nt_headers = (PIMAGE_NT_HEADERS)((uint64_t)local_image + dos_header->e_lfanew);
		auto sect_header = (PIMAGE_SECTION_HEADER)(&nt_headers->OptionalHeader + 1);

		memcpy(fixed_image, local_image, nt_headers->OptionalHeader.SizeOfHeaders);
		for (auto count = 0; count < nt_headers->FileHeader.NumberOfSections; count++)
		{

			memcpy((PBYTE)fixed_image + sect_header[count].VirtualAddress, (PBYTE)local_image + sect_header[count].PointerToRawData, sect_header[count].SizeOfRawData);
		}
	}

	void relocate_base(LPVOID fixed_image, LPVOID target_mem)
	{
		auto nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)fixed_image + ((PIMAGE_DOS_HEADER)fixed_image)->e_lfanew);
		auto base_reloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)fixed_image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		auto delta = (uint64_t)((LPBYTE)target_mem - nt_headers->OptionalHeader.ImageBase);

		for (; base_reloc->VirtualAddress; base_reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)base_reloc + base_reloc->SizeOfBlock))
		{
			auto relocs = (relocation *)(base_reloc + 1);

			for (int x = 0; x < (base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); x++)
			{
				switch (relocs[x].type)
				{
				case IMAGE_REL_BASED_DIR64:
					*(uint64_t *)((LPBYTE)fixed_image + (base_reloc->VirtualAddress + relocs[x].offset)) += delta;
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					*(uint32_t *)((LPBYTE)fixed_image + (base_reloc->VirtualAddress + relocs[x].offset)) += (uint32_t)delta;
					break;

				case IMAGE_REL_BASED_HIGH:
					*(uint16_t *)((LPBYTE)fixed_image + (base_reloc->VirtualAddress + relocs[x].offset)) += HIWORD(delta);
					break;

				case IMAGE_REL_BASED_LOW:
					*(uint16_t *)((LPBYTE)fixed_image + (base_reloc->VirtualAddress + relocs[x].offset)) += LOWORD(delta);
					break;

				case IMAGE_REL_BASED_ABSOLUTE:
					break;

				default:
					printf("Unable to catch relocation type %X", relocs[x].type);
					break;
				}
			}
		}
	}

	void fix_imports(HANDLE target_handle, LPVOID fixed_image, std::string target_process)
	{
		auto nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)fixed_image + ((PIMAGE_DOS_HEADER)fixed_image)->e_lfanew);
		auto import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)fixed_image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		if (import_desc)
		{
			for (; import_desc->Name; import_desc++)
			{
				module_info dependency = mapper::get_dependency(fixed_image, import_desc);
				auto remote_base = process::get_remote_module(GetProcessId(target_handle), dependency.dll_name);
				if (!remote_base)
				{
					for (auto module : module_list)
					{
						if (!_strcmpi(module.dll_name, dependency.dll_name))
							remote_base = (PBYTE)module.base_address;
					}

					if (!remote_base)
					{
						remote_base = (PBYTE)inject_ex(target_handle, target_process, dependency.full_path_name);
					}
				}

				if (remote_base)
				{
					auto _thunk_data = (PIMAGE_THUNK_DATA)((uint64_t)fixed_image + import_desc->FirstThunk);
					auto thunk_data = (PIMAGE_THUNK_DATA)((uint64_t)fixed_image + import_desc->OriginalFirstThunk);

					for (; thunk_data->u1.Function != NULL; thunk_data++, _thunk_data++)
					{
						auto import_name = (PIMAGE_IMPORT_BY_NAME)((uint64_t)fixed_image + thunk_data->u1.AddressOfData);
						_thunk_data->u1.Function = (uint64_t)((uint64_t)GetProcAddress((HMODULE)dependency.base_address, import_name->Name) + (remote_base - dependency.base_address));
					}
				}

			}
		}
		else
		{
			printf("Unable to locate import descriptor\n");
		}
	}

	module_info get_dependency(LPVOID fixed_image, PIMAGE_IMPORT_DESCRIPTOR import_desc)
	{
		auto dependency_base = LoadLibrary((char *)((PBYTE)fixed_image + import_desc->Name));
		char dependency_path[MAX_PATH];
		GetModuleFileNameA(dependency_base, dependency_path, MAX_PATH);
		auto dependency_name = PathFindFileNameA(dependency_path);
		return { dependency_path, dependency_name, dependency_base };
	}

	void call_entrypoint(HANDLE target_handle, PVOID target_mem, PVOID fixed_image)
	{
		DWORD funcProt, caveProt;

		uint8_t shellcode[] = {
			0x9C,															//pushfq
			0x50,															//push rax
			0x53,															//push rbx
			0x51,															//push rcx
			0x52,															//push rdx
			0x41, 0x50,														//push r8
			0x41, 0x51,														//push r9
			0x41, 0x52,														//push r10
			0x41, 0x53,														//push r11
			0x55,															//push rbp
			0x48, 0x89, 0xE5,												//mov rbp, rsp
			0x48, 0x83, 0xE4, 0xF0,											//and rsp, 0xFFFFFFFFFFFFFFF7
			0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,		//mov rcx, 0xCCCCCCCCCCCCCCCC
			0xC7, 0x01, 0x56, 0x02, 0x00, 0x00,								//mov dword ptr ds:[rcx], 0x256
			0x4D, 0x33, 0xC0,												//xor r8, r8
			0xBA, 0x01, 0x00, 0x00, 0x00,									//mov edx, 0x1
			0x51,															//push rcx
			0x48, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,		//mov rbx, 0xCCCCCCCCCCCCCCCC
			0x48, 0x81, 0xEC, 0x08, 0x02, 0x00, 0x00,						//sub rsp, 208
			0xFF, 0xD3,														//call rbx
			0x48, 0x81, 0xC4, 0x08, 0x02, 0x00, 0x00,						//add rsp, 208
			0x59,															//pop rcx
			0xC7, 0x01, 0x63, 0x02, 0x00, 0x00,								//mov dword ptr ds:[rcx], 0x263
			0x48, 0x89, 0xEC,												//mov rsp, rbp
			0x5D,															//pop rbp
			0x41, 0x5B,														//pop r11
			0x41, 0x5A,														//pop r10
			0x41, 0x59,														//pop r9
			0x41, 0x58,														//pop r8
			0x5A,															//pop rdx
			0x59,															//pop rcx
			0x5B,															//pop rbx
			0x58,															//pop rax
			0x9D,															//popfq
			0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,		//mov rax, 0xCCCCCCCCCCCCCCCC
			0xFF, 0xE0														//jmp rax
		};

		auto codecave = (PVOID)PE::find_code_cave(LoadLibrary("kernel32.dll"), sizeof(shellcode));
		auto target_function = PE::get_exported_function(vuln_module, vuln_function);
		auto entry_point = (PBYTE)target_mem + PE::get_entrypoint_offset(fixed_image);

		*(uint64_t *)(shellcode + 23) = (uint64_t)target_mem;
		*(uint64_t *)(shellcode + 48) = (uint64_t)entry_point;
		*(uint64_t *)(shellcode + 98) = (uint64_t)target_function;

		if (target_function && codecave)
		{
			if (VirtualProtectEx(target_handle, target_function, sizeof(ULONGLONG), PAGE_EXECUTE_READWRITE, &funcProt) && VirtualProtectEx(target_handle, codecave, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &caveProt))
			{
				uint64_t overwritten_bytes;

				auto success = ReadProcessMemory(target_handle, target_function, &overwritten_bytes, sizeof(uint64_t), NULL);
				success &= WriteProcessMemory(target_handle, codecave, &shellcode, sizeof(shellcode), NULL);
				if (!success)
				{
					printf("Unable to read vulnerable function or write shellcode: %X\n", GetLastError());
				}

				uint8_t *jmp = shellcode::relative_jmp_64((PBYTE)codecave - target_function - 5);
				WriteProcessMemory(target_handle, target_function, jmp, sizeof(ULONGLONG), NULL);

				mapper::wait_for_exit(target_handle, target_mem, target_function, overwritten_bytes);

				mapper::post_injection(target_handle, target_mem, codecave);

				VirtualProtectEx(target_handle, target_function, sizeof(ULONGLONG), funcProt, &funcProt);
				VirtualProtectEx(target_handle, codecave, sizeof(shellcode), caveProt, &caveProt);
			}
			else
			{
				printf("Unable to gain access codecave or target function: %X\n", GetLastError());
			}
		}
		else
		{
			printf("Unable to find codecave or target function: %s:%llx, %s:%llx\n", vuln_module, codecave, vuln_function, target_function);
		}
	}

	void wait_for_exit(HANDLE target_handle, PVOID target_mem, PVOID function_address, uint64_t overwritten_bytes)
	{
		USHORT injection_status;
		bool function_restored = false;
		while (ReadProcessMemory(target_handle, target_mem, &injection_status, 2, NULL))
		{
			if (injection_status == RESTORE_FUNCTION && !function_restored)
			{
				WriteProcessMemory(target_handle, function_address, &overwritten_bytes, sizeof(uint64_t), NULL);
				function_restored = true;
			}
			if (injection_status == INJECTION_SUCCESS)
			{
				if (!function_restored)
					WriteProcessMemory(target_handle, function_address, &overwritten_bytes, sizeof(uint64_t), NULL);
				break;
			}

		}
	}

	void post_injection(HANDLE target_handle, PVOID target_mem, PVOID codecave)
	{
		auto zero_mem = VirtualAlloc(NULL, sizeof(codecave), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (zero_mem)
		{
			RtlZeroMemory(zero_mem, sizeof(codecave));
			WriteProcessMemory(target_handle, codecave, &zero_mem, sizeof(codecave), NULL);
			WriteProcessMemory(target_handle, target_mem, &codecave, 4096, NULL);

			VirtualFree(zero_mem, NULL, MEM_RELEASE);
		}
		else
		{
			printf("Unable to allocate buffer to zero codecave: %X\n", GetLastError());
		}
	}
}