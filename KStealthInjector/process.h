#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <map>

namespace process
{
	uint32_t get_process_id(std::string process_name);
	HANDLE get_target_handle(uint32_t target_pid, uint32_t desired_access);
	std::map<std::string, uint64_t> get_imported_modules(uint32_t target_process);

}