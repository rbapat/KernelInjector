#include <Windows.h>
#include <iostream>

#include "process.h"
#include "mapper.h"

int main()
{
	mapper::inject("FortniteLauncher.exe", "C:\\payload64.dll");
	getchar();
	return 0;
}