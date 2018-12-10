#pragma once
#pragma comment(lib, "Shlwapi.lib")
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>	
#include <Shlwapi.h>

#include "utils.h"
#include "process.h"
#include "PE.h"
#include "shellcode.h"
#include "xigndriver.h"

#define INJECTION_SUCCESS	0x263
#define RESTORE_FUNCTION	0x256

struct module_info
{
	LPCSTR full_path_name;
	LPCSTR dll_name;
	PVOID base_address;
};

struct relocation
{
	WORD offset : 12;
	WORD type : 4;
};

namespace mapper
{
	PVOID inject(std::string target_proc, std::string dll);
	PVOID inject_ex(HANDLE target_handle, std::string target_proc, std::string dll);
	void copy_sections(LPVOID local_image, LPVOID fixed_image);
	void relocate_base(LPVOID fixed_image, LPVOID target_mem);
	void fix_imports(HANDLE target_handle, LPVOID fixed_image, std::string target_process);
	module_info get_dependency(LPVOID fixed_image, PIMAGE_IMPORT_DESCRIPTOR import_desc);
	void call_entrypoint(HANDLE target_handle, PVOID target_mem, PVOID fixed_image);
	void wait_for_exit(HANDLE target_handle, PVOID target_mem, PVOID function_address, uint64_t overwritten_bytes);
	void post_injection(HANDLE target_handle, PVOID target_mem, PVOID codecave);
}