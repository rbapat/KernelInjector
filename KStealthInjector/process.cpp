#include "process.h"

namespace process
{
	uint32_t get_process_id(std::string process_name)
	{
		
		auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 pe32 = PROCESSENTRY32{ sizeof(PROCESSENTRY32) };
		if (Process32First(hSnapshot, &pe32))
		{
			do
			{
				if (_strcmpi(process_name.c_str(), pe32.szExeFile) == 0)
				{
					CloseHandle(hSnapshot);
					return pe32.th32ProcessID;
				}
			} while (Process32Next(hSnapshot, &pe32));
		}

		CloseHandle(hSnapshot);
		return 0;
	}

	HANDLE get_target_handle(uint32_t target_pid)
	{
		return xigndriver::open_process(target_pid);
	}

	std::map<std::string, uint32_t> get_imported_modules(uint32_t target_process)
	{
		std::map<std::string, uint32_t> imported_modules;

		auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, target_process);
		MODULEENTRY32 me32 = MODULEENTRY32{ sizeof(MODULEENTRY32) };

		if (Module32First(hSnapshot, &me32))
		{
			do
			{
				imported_modules.insert(std::make_pair(me32.szExePath, (uint32_t)me32.modBaseAddr));
			} while (Module32Next(hSnapshot, &me32));
		}

		CloseHandle(hSnapshot);
		return imported_modules;
	}

	uint32_t inject_function(HANDLE target_handle, uint32_t stub_size, LPVOID loader_stub, LPVOID lpParams)
	{
		auto targetStub = VirtualAllocEx(target_handle, NULL, stub_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!targetStub)
		{
			printf("Unable to allocate %d bytes for loader stub in target process: %d\n", stub_size, GetLastError());
			return false;
		}

		if (!WriteProcessMemory(target_handle, targetStub, loader_stub, stub_size, NULL))
		{
			printf("Unable to write loader stub to target process: %d\n", GetLastError());
			VirtualFreeEx(target_handle, targetStub, NULL, MEM_RELEASE);
			return false;
		}

		auto hThread = CreateRemoteThread(target_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)targetStub, lpParams, NULL, NULL);
		if (hThread == INVALID_HANDLE_VALUE)
		{
			printf("Unable to create loader thread in target process: %d\n", GetLastError());
			VirtualFreeEx(target_handle, targetStub, NULL, MEM_RELEASE);
			return false;
		}

		WaitForSingleObject(hThread, INFINITE);

		CloseHandle(hThread);
		//VirtualFreeEx(target_handle, targetStub, NULL, MEM_RELEASE);

		return true;
	}
}