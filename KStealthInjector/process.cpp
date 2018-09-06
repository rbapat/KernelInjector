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

	HANDLE get_target_handle(uint32_t target_pid, uint32_t desired_access)
	{
		return OpenProcess(desired_access, false, target_pid);
	}

	std::map<std::string, uint64_t> get_imported_modules(uint32_t target_process)
	{
		std::map<std::string, uint64_t> imported_modules;

		auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, target_process);
		MODULEENTRY32 me32 = MODULEENTRY32{ sizeof(MODULEENTRY32) };

		if (Module32First(hSnapshot, &me32))
		{
			do
			{
				imported_modules.insert(std::make_pair(me32.szModule, (uint64_t)me32.modBaseAddr));
			} while (Module32Next(hSnapshot, &me32));
		}

		CloseHandle(hSnapshot);
		return imported_modules;
	}
}