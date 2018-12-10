#include "process.h"

namespace process
{
	uint64_t get_process_id(std::string process_name)
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

	PBYTE get_remote_module(uint64_t target_pid, LPCSTR module_name)
	{
		auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, target_pid);
		MODULEENTRY32 me32 = MODULEENTRY32{ sizeof(MODULEENTRY32) };

		if (Module32First(hSnapshot, &me32))
		{
			do
			{
				if (!_strcmpi(me32.szModule, module_name))
					return me32.modBaseAddr;
			} while (Module32Next(hSnapshot, &me32));
		}

		CloseHandle(hSnapshot);
		return 0;
	}

	HANDLE get_vulnerable_thread(HANDLE process_handle)
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		THREADENTRY32 te32;
		te32.dwSize = sizeof(THREADENTRY32);
		auto process_id = GetProcessId(process_handle);

		if (Thread32First(snapshot, &te32)) {
			while (Thread32Next(snapshot, &te32)) {
				if (te32.th32OwnerProcessID == process_id) {
					CloseHandle(snapshot);
					return OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
				}
			}
		}

		CloseHandle(snapshot);
		return 0;
	}
}