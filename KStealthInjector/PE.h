#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

#include "utils.h"

namespace PE
{
	PVOID get_entrypoint(PVOID image);
	uint32_t get_entrypoint_offset(PVOID image);
	PVOID get_exported_function(LPCSTR module_name, LPCSTR function_name);
	uint64_t find_code_cave(PVOID image, uint32_t size);
}