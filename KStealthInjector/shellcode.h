#pragma once
#include <Windows.h>
#include <iostream>

namespace shellcode
{
	uint8_t *relative_jmp_64(uint32_t delta);
}