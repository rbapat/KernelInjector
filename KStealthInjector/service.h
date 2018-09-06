#pragma once
#include <Windows.h>
#include <string>

namespace service
{
	std::uint32_t start_service(std::string driver_path, std::string service_name);
	bool exists(std::string service_name);
	bool running(std::string service_name);
	HANDLE get_handle(std::string service_name);
	std::uint32_t kill_service(std::string service_name);
}