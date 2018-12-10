#include "service.h"

namespace service
{
	std::uint64_t start_service(std::string driver_path, std::string service_name)
	{
		if (service::running(service_name))
			return 1;

		SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
		if (!hSCManager)
		{
			printf("Service::start_service | Unable to open SCManager: %d\n", GetLastError());
			return 0;
		}

		SC_HANDLE hService = CreateService(hSCManager, service_name.c_str(), service_name.c_str(), SC_MANAGER_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driver_path.c_str(), NULL, NULL, NULL, NULL, NULL);
		if (!hService && GetLastError() == ERROR_SERVICE_EXISTS)
		{
			hService = OpenService(hSCManager, service_name.c_str(), SERVICE_ALL_ACCESS);
			if (!hService)
			{
				printf("Service::start_service | Unable to open service: %d\n", GetLastError());
				CloseServiceHandle(hSCManager);
				return 0;
			}
		}
		else if (!hService)
		{
			printf("Service::start_service | Unable to start service: %d\n", GetLastError());
			CloseServiceHandle(hSCManager);
			return 0;
		}

		if (StartService(hService, NULL, NULL))
		{
			CloseServiceHandle(hSCManager);
			CloseServiceHandle(hService);
			return 1;
		}
		else
		{
			printf("Service::start_service | Couldn't Start Service: %d\n", GetLastError());
			CloseServiceHandle(hSCManager);
			CloseServiceHandle(hService);
			return 0;
		}
	}

	bool exists(std::string service_name)
	{
		SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
		if (!hSCManager)
		{
			printf("Service::exists | Unable to open SCManager: %d\n", GetLastError());
			return NULL;
		}

		SC_HANDLE hService = OpenService(hSCManager, service_name.c_str(), SERVICE_ALL_ACCESS);
		if (hService)
		{
			CloseServiceHandle(hSCManager);
			CloseServiceHandle(hService);
			return true;
		}
		else if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			CloseServiceHandle(hSCManager);
			CloseServiceHandle(hService);
			return false;
		}

		printf("Service::exists | Unable to open service: %d\n", GetLastError());
		CloseServiceHandle(hSCManager);
		CloseServiceHandle(hService);
		return NULL;
	}

	bool running(std::string service_name)
	{
		SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
		if (!hSCManager)
		{
			printf("Service::running | Unable to open SCManager: %d\n", GetLastError());
			return NULL;
		}

		SC_HANDLE hService = OpenService(hSCManager, service_name.c_str(), SERVICE_ALL_ACCESS);
		if (hService)
		{
			SERVICE_STATUS_PROCESS  status;
			DWORD dwBytes;
			if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (PBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &dwBytes))
			{
				printf("Service::running | Unable to query service status: %d\n", GetLastError());
				CloseServiceHandle(hSCManager);
				CloseServiceHandle(hService);
				return NULL;
			}
			CloseServiceHandle(hSCManager);
			CloseServiceHandle(hService);
			return status.dwCurrentState == 4;
		}
		else if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			CloseServiceHandle(hSCManager);
			CloseServiceHandle(hService);
			return false;
		}

		printf("Service::running | Unable to open service: %d\n", GetLastError());
		CloseServiceHandle(hSCManager);
		CloseServiceHandle(hService);
		return NULL;
	}

	HANDLE get_handle(std::string service_name)
	{
		char driver_path[256];
		sprintf_s(driver_path, "\\\\.\\%s", service_name.c_str());
		return CreateFile(driver_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	}
	std::uint64_t kill_service(std::string service_name)
	{
		if (service::exists(service_name))
		{
			SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
			SERVICE_STATUS status;
			if (!hSCManager)
			{
				printf("Service::kill_service | Unable to open SCManager: %d\n", GetLastError());
				return 0;
			}

			SC_HANDLE hService = OpenService(hSCManager, service_name.c_str(), SERVICE_ALL_ACCESS);
			if (!hService)
			{
				printf("Service::kill_service | Unable to open service: %d\n", GetLastError());
				CloseServiceHandle(hSCManager);
				return 0;
			}

			if (!ControlService(hService, SERVICE_CONTROL_STOP, &status))
			{
				printf("Service::kill_service | Unable to stop service: %d\n", GetLastError());
				CloseServiceHandle(hSCManager);
				CloseServiceHandle(hService);
				return 0;
			}

			if (!DeleteService(hService))
			{
				printf("Service::kill_service | Unable to delete service: %d\n", GetLastError());
				CloseServiceHandle(hSCManager);
				CloseServiceHandle(hService);
				return 0;
			}

			CloseServiceHandle(hSCManager);
			CloseServiceHandle(hService);
		}

		return 1;
	}
}