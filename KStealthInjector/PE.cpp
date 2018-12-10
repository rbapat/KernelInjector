#include "PE.h"


namespace PE
{
	PVOID get_entrypoint(PVOID image)
	{
		return ((PBYTE)image + PE::get_entrypoint_offset(image));
	}

	uint32_t get_entrypoint_offset(PVOID image)
	{
		auto dosHeader = (PIMAGE_DOS_HEADER)image;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((uint64_t)image + dosHeader->e_lfanew);
		return ntHeaders->OptionalHeader.AddressOfEntryPoint;
	}

	PVOID get_exported_function(LPCSTR module_name, LPCSTR function_name)
	{
		PVOID image_base = LoadLibrary(module_name);
		PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)image_base;
		PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((PUCHAR)image_base + pIDH->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)image_base + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		PULONG Functions = (PULONG)((PUCHAR)image_base + pIED->AddressOfFunctions);
		PULONG Names = (PULONG)((PUCHAR)image_base + pIED->AddressOfNames);
		PUSHORT Ordinals = (PUSHORT)((PUCHAR)image_base + pIED->AddressOfNameOrdinals);
		UINT64 i = 0;
		for (i = 0; i < pIED->NumberOfNames; i++)
		{
			if (!strcmp((char*)image_base + Names[i], function_name))
			{
				return ((PUCHAR)image_base + Functions[Ordinals[i]]);
			}
		}

		return NULL;
	}

	uint64_t find_code_cave(PVOID image, uint32_t size)
	{
		auto dos_header = (PIMAGE_DOS_HEADER)image;
		auto nt_headers = (PIMAGE_NT_HEADERS64)((uint64_t)image + dos_header->e_lfanew);

		for (int x = 0, count = 0; x < nt_headers->OptionalHeader.SizeOfImage; x++)
		{
			auto item = *(uint8_t *)((uint64_t)image + x);

			if (item == 0x00 || item == 0xCC)
				count++;
			else
				count = 0;

			if (count > size + 2)
			{
				return ((uint64_t)image + x - size);
			}

		}

		return NULL;
	}
}

/*
PE::PE(const char *dll_path)
{
	auto temp_mem = utils::read_file(dll_path);
	auto ntHeaders = (PIMAGE_NT_HEADERS)((uint32_t)temp_mem + ((PIMAGE_DOS_HEADER)temp_mem)->e_lfanew);

	image_mem = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	parse_sections(image_mem, temp_mem);
	parse_imports();
	parse_strings();

	VirtualFree(temp_mem, NULL, MEM_RELEASE);

	print_info();
}

void PE::parse_sections(LPVOID dst_image, LPVOID src_image)
{
	auto dos_header = (PIMAGE_DOS_HEADER)src_image;
	auto nt_headers = (PIMAGE_NT_HEADERS32)((uint32_t)src_image + dos_header->e_lfanew);
	auto sect_header = (PIMAGE_SECTION_HEADER)(&nt_headers->OptionalHeader + 1);

	memcpy(dst_image, src_image, nt_headers->OptionalHeader.SizeOfHeaders);
	for (auto count = 0; count < nt_headers->FileHeader.NumberOfSections; count++)
	{
		sections.push_back((const char *)sect_header[count].Name);
		memcpy((PBYTE)dst_image + sect_header[count].VirtualAddress, (PBYTE)src_image + sect_header[count].PointerToRawData, sect_header[count].SizeOfRawData);
	}
}

void PE::parse_imports()
{
	auto nt_headers = (PIMAGE_NT_HEADERS)((LPBYTE)image_mem + ((PIMAGE_DOS_HEADER)image_mem)->e_lfanew);
	auto import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image_mem + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	for (; import_desc->Name; import_desc++)
	{
		imports.push_back(imported_module{ (LPCSTR)((uint32_t)image_mem + import_desc->Name), std::vector<std::string>() });

		auto _thunk_data = (PIMAGE_THUNK_DATA)((uint32_t)image_mem + import_desc->FirstThunk);
		auto thunk_data = (PIMAGE_THUNK_DATA)((uint32_t)image_mem + import_desc->OriginalFirstThunk);

		for (; thunk_data->u1.Function != NULL; thunk_data++, _thunk_data++)
		{
			auto import_name = (PIMAGE_IMPORT_BY_NAME)((uint32_t)image_mem + thunk_data->u1.AddressOfData);
			printf("%s::%s %X\n", (LPCSTR)((uint32_t)image_mem + import_desc->Name), import_name->Name,thunk_data->u1.Function);

			imports.back().function_names.push_back(import_name->Name);
		}
	}
}

void PE::parse_strings()
{
	auto dosHeader = (PIMAGE_DOS_HEADER)image_mem;
	auto ntHeaders = (PIMAGE_NT_HEADERS)((uint32_t)image_mem + dosHeader->e_lfanew);
	auto sectHeader = (PIMAGE_SECTION_HEADER)(&ntHeaders->OptionalHeader + 1);

	for (auto count = 0; count < ntHeaders->FileHeader.NumberOfSections; count++)
	{
		auto section = (PBYTE)image_mem + sectHeader[count].PointerToRawData;
		auto size = sectHeader[count].SizeOfRawData;
		auto len = 0, df = 0;
		if (!_strcmpi((const char *)sectHeader[count].Name, ".rdata"))
		{
			for (auto index = 0; index + len < size; len++)
			{
				auto character = *(BYTE *)(section + index + len);

				if (character == 0x00)
				{
					if (df && len > 1)
					{
						df = false;
						len++;
						strings.push_back((const char *)(section + index));
						index += len;
						len = -1;
					}
					else
					{
						index += len + 1;
						len = -1;
					}
				}
				else
					df = true;

				if (character && (character > 126 || character < 32))
				{
					index += len + 1;
					len = -1;
				}
			}
		}
	}
}

void PE::print_info()
{
	for (auto section : sections)
		printf("[Section]: %s\n", section.c_str());

	for (auto imported_mod : imports)
		for (auto funct : imported_mod.function_names)
			printf("[Import] : %s::%s\n", imported_mod.module_name.c_str(), funct.c_str());

	for (auto string : strings)
		printf("[String] : %s\n", string.c_str());
}
*/