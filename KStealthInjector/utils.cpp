#include "utils.h"

namespace utils
{
	LPVOID read_file(std::string file_path)
	{
		DWORD dwBytesRead;

		auto hFile = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
		if ((HANDLE)hFile == INVALID_HANDLE_VALUE)
		{
			printf("Unable to CreateFile %s: %d\n", file_path, GetLastError());
			return 0;
		}

		auto file_size = GetFileSize((HANDLE)hFile, NULL);
		auto lpBuffer = VirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!lpBuffer)
		{
			printf("Unable to Allocate Memory For Buffer: %d\n", GetLastError());
			return 0;
		}

		if (!ReadFile((HANDLE)hFile, lpBuffer, file_size, &dwBytesRead, NULL))
		{
			printf("Unable to ReadFile: %d\n", GetLastError());
			return 0;
		}

		return lpBuffer;
	}
}