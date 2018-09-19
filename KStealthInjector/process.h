#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <map>

#include "xigndriver.h"

namespace process
{
	uint32_t get_process_id(std::string process_name);
	HANDLE get_target_handle(uint32_t target_pid);
	std::map<std::string, uint32_t> get_imported_modules(uint32_t target_process);
	uint32_t inject_function(HANDLE target_handle, uint32_t stub_size, LPVOID loader_stub, LPVOID lpParams);

}