#include <Windows.h>
#include <iostream>

#include "service.h"
#include "process.h"
#include "xigndriver.h"


int main()
{	
	xigndriver::initialize();

	TerminateProcess(xigndriver::open_process("Engine.exe"), 1);

	getchar();
	return 0;
}