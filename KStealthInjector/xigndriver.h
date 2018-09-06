#pragma once
#include <Windows.h>
#include <iostream>
#include <string>

#include "service.h"
#include "process.h"

namespace xigndriver
{
	void initialize();
	HANDLE open_process(std::string process_name);
	HANDLE open_process(uint32_t process_id);

	struct xign_packet
	{
		uint32_t size;
		uint32_t magic_num;
		uint32_t control_val;
		uint32_t function_type;
		uint64_t output;
		uint32_t process_id;
		uint32_t access_mode;
		uint8_t pad[592];
	};

	struct xign_response
	{
		uint32_t size;
		uint32_t magic_num;
		uint32_t control_val;
		NTSTATUS status;
		HANDLE process_handle;
	};
}