#include <Windows.h>
#include <iostream>

#include "process.h"
#include "mapper.h"

int main()
{
	mapper::inject("ToInject.dll", "Target.exe");
	return 0;
}