#pragma once
#include <Windows.h>
#include <Shlwapi.h>
#include <iostream>
#include <string.h>
#include <map>

#include "process.h"
#include "utils.h"


#pragma comment(lib, "Shlwapi.lib")

namespace mapper
{
	PBYTE inject(std::string target_dll, std::string target_exe);
	PBYTE inject_ex(HANDLE target_handle, std::string dll_name, std::map<std::string, uint32_t> &imported_modules);
	void copy_sections(HANDLE target_handle, LPVOID local_image, LPVOID target_image);
	void relocate_base(LPVOID target_image, LPVOID target_mem);
	void fix_imports(HANDLE target_handle, LPVOID target_image, std::map<std::string, uint32_t> &imported_modules);
	uint32_t contains(std::map<std::string, uint32_t> imported_modules, LPCSTR module_name);
	uint32_t LoadDll(LPVOID targetImage);
	void LoadDllEnd();
}
