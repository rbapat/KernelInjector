#include "xigndriver.h"
#include "driver_bin.h"

namespace xigndriver
{
	void initialize()
	{
		service::start_service("C:\\Windows\\System32\\iutwfsitabnsahbsogiwbiwslhf.sys", "iutwfsitabnsahbsogiwbiwslhf");
	}

	HANDLE open_process(std::string process_name)
	{
		auto process_id = process::get_process_id(process_name.c_str());
		while (!process_id)
			process_id = process::get_process_id(process_name.c_str());

		return xigndriver::open_process(process_id);
	}

	HANDLE open_process(uint32_t process_id)
	{
		xign_packet *request = new xign_packet();
		xign_response *response = new xign_response();
		
		DWORD bytes_written;
		HANDLE hTarget;

		request->size = 0x270;
		request->magic_num = 0x345821AB;
		request->control_val = 0x13371337;
		request->function_type = 785;
		request->process_id = process_id;
		request->access_mode = PROCESS_ALL_ACCESS;
		request->output = (uint64_t)response;

		auto hDriver = service::get_handle("iutwfsitabnsahbsogiwbiwslhf");
		
		if (!WriteFile(hDriver, request, sizeof(xign_packet), &bytes_written, NULL)) {
			printf("Driver Write Failed: %d\n", GetLastError());
			hTarget = NULL;
		}

		hTarget = response->process_handle;

		CloseHandle(hDriver);
		return hTarget;
	}
}