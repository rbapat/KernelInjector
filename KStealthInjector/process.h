#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>

namespace process
{
	uint64_t get_process_id(std::string process_name);
	HANDLE get_vulnerable_thread(HANDLE process_handle);
	PBYTE get_remote_module(uint64_t target_pid, LPCSTR module_name);
}