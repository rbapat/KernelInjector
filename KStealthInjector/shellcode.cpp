#include "shellcode.h"

namespace shellcode
{
	uint8_t *relative_jmp_64(uint32_t delta)
	{
		uint8_t jmp[] = { 0xE9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
		*(uint32_t *)(jmp + 1) = (uint32_t)delta;

		return jmp;
	}
}