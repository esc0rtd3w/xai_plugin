//#include <string.h>
//#include <cell/fs/cell_fs_file_api.h>
//#include <sys/fs_external.h>
//#include <sys/timer.h>
#include "hen.h"
#include "functions.h"
#include "gccpch.h"
#include "log.h"
#include "hfw_settings.h"
#include "badwdsd.h"
#include "rsx.h"
#include "lv1.h"

uint64_t peekq(uint64_t addr) // peekq(0x80000000002E9D70ULL)==0x4345580000000000ULL
{
	system_call_1(6, addr);
	return_to_user_prog(uint64_t);
}

uint32_t peekq32(uint64_t addr) 
{
	return (peekq(addr) >> 32) & 0xFFFFFFFFUL;
}

void pokeq( uint64_t addr, uint64_t val) // pokeq(0x800000000000171CULL,       0x7C0802A6F8010010ULL);
{
	system_call_2(7, addr, val);
}

void pokeq32(uint64_t address, uint32_t value) 
{
	uint64_t old_value = peekq(address);
	pokeq(address, ((uint64_t)value << 32) | (old_value & 0xFFFFFFFFULL));
}

/*static inline uint64_t lv1_read2(uint64_t addr)
{
    uint64_t v = 0;
    // read exactly 8 bytes into v
    lv1_read(addr, sizeof(v), &v);
    return v;
}

static inline void lv1_write2(uint64_t addr, uint64_t value)
{
    // write exactly 8 bytes from value
    lv1_write(addr, sizeof(value), &value);
}*/

process_id_t vsh_pid = 0;

int poke_vsh(uint64_t address, char *buf, int size)
{
	if (!vsh_pid)
	{
		uint32_t tmp_pid_list[MAX_PROCESS];
		char name[25];
		int i;
		system_call_3(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_ALL_PROC_PID, (uint64_t)(uint32_t)tmp_pid_list);
		for (i = 0; i<MAX_PROCESS; i++)
		{
			system_call_4(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_PROC_NAME_BY_PID, tmp_pid_list[i], (uint64_t)(uint32_t)name);
			if (strstr(name, "vsh"))
			{
				vsh_pid = tmp_pid_list[i];
				break;
			}
		}
		if (!vsh_pid)
			return -1;
	}
	system_call_6(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SET_PROC_MEM, vsh_pid, address, (uint64_t)(uint32_t)buf, size);
}

int read_vsh(uint64_t address, char *buf, int size)
{
	if (!vsh_pid)
	{
		uint32_t tmp_pid_list[MAX_PROCESS];
		char name[25];
		int i;
		system_call_3(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_ALL_PROC_PID, (uint64_t)(uint32_t)tmp_pid_list);
		for (i = 0; i<MAX_PROCESS; i++)
		{
			system_call_4(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_PROC_NAME_BY_PID, tmp_pid_list[i], (uint64_t)(uint32_t)name);
			if (strstr(name, "vsh"))
			{
				vsh_pid = tmp_pid_list[i];
				break;
			}
		}
		if (!vsh_pid)
			return -1;
	}
	system_call_6(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_PROC_MEM, vsh_pid, address, (uint64_t)(uint32_t)buf, size);
}

//TODO: Fix this function
void psn_patch(uint32_t paddr, uint32_t pbytes, bool reset)
{
	if (reset)
	{
		reset_psn_patches();
		poke_vsh(paddr, (char*)&pbytes, 4);
	}
	else
	{
		poke_vsh(paddr, (char*)&pbytes, 4);
	}
}

void reset_psn_patches()
{
	uint32_t amazon1 = 0x3D200072;
	uint32_t amazon2 = 0x7C0802A6;
	//uint32_t hulu1 = 0x2B9D0001;
	//uint32_t hulu2 = 0x3C608002;
	uint32_t youtube = 0x2F800000;
	poke_vsh(0x242454, (char*)&amazon1, 4);
	poke_vsh(0x242458, (char*)&amazon2, 4);
	//poke_vsh(0x2455BC, (char*)&hulu1, 4);
	//poke_vsh(0x2455C0, (char*)&hulu2, 4);
	poke_vsh(0x1B60A4, (char*)&youtube, 4);
}

void kpatch(uint64_t kaddr, uint64_t kbytes)
{
	peekq(kaddr);
	showMessageRaw(msgf("peekq %08X: Old Bytes %08X\n", kaddr, peekq(kaddr)), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	pokeq(kaddr, kbytes);

	peekq(kaddr);
	showMessageRaw(msgf("peekq %08X: New Bytes %08X\n", kaddr, peekq(kaddr)), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

/*void convert_utf16_to_ascii(const uint16_t *utf16, char *ascii, size_t maxLen)
{
    size_t i = 0;
    while(i < maxLen - 1 && utf16[i] != 0)
    {
        ascii[i] = (char)utf16[i];
        i++;
    }
    ascii[i] = '\0';
}

void ascii_to_utf16(const char *ascii, uint16_t *utf16, size_t maxLen)
{
    size_t i = 0;
    while (i < maxLen - 1 && ascii[i] != '\0')
    {
         utf16[i] = (uint16_t)ascii[i];
         i++;
    }
    utf16[i] = 0;
}

int getHexInput(const char *prompt, uint64_t *outValue)
{
    int ret;
    CellOskDialogParam dialogParam;
    memset(&dialogParam, 0, sizeof(dialogParam));

    // Configure dialog parameters.
    dialogParam.allowOskPanelFlg = CELL_OSKDIALOG_FULLKEY_PANEL;
    dialogParam.firstViewPanel = CELL_OSKDIALOG_PANELMODE_ALPHABET;
    dialogParam.controlPoint.x = 100.0f;
    dialogParam.controlPoint.y = 100.0f;
    dialogParam.prohibitFlgs = CELL_OSKDIALOG_NO_RETURN;

    // Create local buffers for the UTF-16 prompt and initial text.
    uint16_t utf16Prompt[256];
    uint16_t utf16InitText[16];
    ascii_to_utf16(prompt, utf16Prompt, sizeof(utf16Prompt) / sizeof(uint16_t));
    ascii_to_utf16("0x", utf16InitText, sizeof(utf16InitText) / sizeof(uint16_t));

    CellOskDialogInputFieldInfo inputFieldInfo;
    // Use the converted UTF-16 strings instead of L(prompt)
    inputFieldInfo.message = utf16Prompt;
    inputFieldInfo.init_text = utf16InitText;
    inputFieldInfo.limit_length = 32;

    // Load the OSK dialog asynchronously.
    ret = cellOskDialogLoadAsync(0, &dialogParam, &inputFieldInfo);
    if(ret != 0)
    {
        printf("cellOskDialogLoadAsync failed: 0x%x\n", ret);
        return ret;
    }

    // Poll for user input.
    CellOskDialogCallbackReturnParam callbackParam;
    memset(&callbackParam, 0, sizeof(callbackParam));
    while (1)
    {
        ret = cellOskDialogGetInputText(&callbackParam);
        if(ret == 0)
        {
            if (callbackParam.result == CELL_OSKDIALOG_INPUT_FIELD_RESULT_OK ||
                callbackParam.result == CELL_OSKDIALOG_INPUT_FIELD_RESULT_CANCELED ||
                callbackParam.result == CELL_OSKDIALOG_INPUT_FIELD_RESULT_ABORT)
            {
                break;
            }
        }
        sys_timer_usleep(100 * 1000);  // wait 100ms
    }

    // Unload the OSK dialog.
    cellOskDialogUnloadAsync(&callbackParam);

    // If the input was confirmed, convert the UTF-16 result to ASCII.
    if (callbackParam.result == CELL_OSKDIALOG_INPUT_FIELD_RESULT_OK)
    {
        char asciiInput[256];
        // Here, convert_utf16_to_ascii() converts the OSK result (callbackParam.pResultString) into a C string.
        convert_utf16_to_ascii(callbackParam.pResultString, asciiInput, sizeof(asciiInput));
        printf("User entered: %s\n", asciiInput);
        *outValue = strtoull(asciiInput, NULL, 16);
        return 0;
    }
    else
    {
        printf("Input canceled or error (result = %d)\n", callbackParam.result);
        return -1;
    }
}*/

void check_temperature()
{
	uint32_t temp_cpu_c = 0, temp_rsx_c = 0;
	uint32_t temp_cpu_f = 0, temp_rsx_f = 0;

	// Enabling sys_game_get_temperature() in 4.90 CEX
	pokeq32(0x800000000000C6A4ULL, 0x38600000);

	sys_game_get_temperature(0, &temp_cpu_c);
    sys_game_get_temperature(1, &temp_rsx_c);

	temp_cpu_f = celsius_to_fahrenheit(&temp_cpu_c);
	temp_rsx_f = celsius_to_fahrenheit(&temp_rsx_c);

	if(!temp_cpu_c || !temp_rsx_c || !temp_cpu_f || !temp_rsx_f)
		showMessageRaw(msgf("Unable to get temperature values"), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else
		showMessageRaw(msgf("[CPU: %uC] - [RSX: %uC]\n[CPU: %uF] - [RSX: %uF]", (int)temp_cpu_c, (int)temp_rsx_c, (int)temp_cpu_f, (int)temp_rsx_f), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

void dump_idps()
{
	uint8_t idps[0x10];
	memset(idps, 0, 0x10);
	int ret = sys_ss_get_console_id(idps);
	if (ret == EPERM)
		ret = cellSsAimGetDeviceId(idps);
	if (ret != CELL_OK)
	{
		showMessageRaw(msgf("IDPS Dump failed: %x\n", ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}
	log_key("IDPS", idps);
	showMessageRaw(msgf("IDPS Dumped!\n%08X%08X\n%08X%08X", *(int*)idps, *((int*)idps + 1), *((int*)idps + 2), *((int*)idps + 3)), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

void dump_psid()
{
	uint8_t psid[0x10];
	memset(psid, 0, 0x10);
	int ret = sys_ss_get_open_psid(psid);
	if (ret != CELL_OK)
	{
		showMessageRaw(msgf("PSID Dump failed: %x\n", ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return;
	}
	log_key("PSID", psid);
	showMessageRaw(msgf("PSID Dumped!\n%08X%08X\n%08X%08X", *(int*)psid, *((int*)psid + 1), *((int*)psid + 2), *((int*)psid + 3)), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
}

int dump_lv2()
{
	int final_offset;
	int mem = 0, max_offset = 0x40000;
	int fd, fseek_offset = 0, start_offset = 0;

	char usb[120], dump_file_path[120], lv_file[120];

	uint8_t platform_info[0x18];
	uint64_t nrw, seek, offset_dumped;
	CellFsStat st;	

	// Check if CFW Syscalls are disabled
	if(peekq(0x8000000000363BE0ULL) == 0xFFFFFFFF80010003ULL)
	{
		showMessageRaw("Syscalls are disabled", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
		return 1;
	}
	
    system_call_1(387, (uint64_t)platform_info);

	final_offset = 0x800000ULL;	

	vsh_sprintf(lv_file, LV2_DUMP, platform_info[0], platform_info[1], platform_info[2] >> 4);	
	vsh_sprintf(dump_file_path, "%s/%s", (int)TMP_FOLDER, (int)lv_file);

	for(int i = 0; i < 127; i++)
	{				
		vsh_sprintf(usb, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(usb, &st))
		{
			vsh_sprintf(dump_file_path, "%s/%s", (int)usb, (int)lv_file);
			break;
		}
	}

	if(cellFsOpen(dump_file_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != SUCCEEDED)
	{
		showMessageRaw("An error occurred while dumping LV2", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}

	cellFsChmod(dump_file_path, 0666);

	showMessageRaw("Dumping LV2, please wait...", (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	// Quickest method to dump LV2 and LV1 through xai_plugin
	// Default method will take at least two minutes to dump LV2, and even more for LV1
	uint8_t *dump = (uint8_t *)malloc_(0x40000);
	memset(dump, 0, 0x40000);			

	for(uint64_t offset = start_offset; offset < max_offset; offset += 8)
	{
		offset_dumped = peekq(0x8000000000000000ULL + offset);

		memcpy(dump + mem, &offset_dumped, 8);

		mem += 8;

		if(offset == max_offset - 8)
		{
			//cellFsLseek(fd, fseek_offset, SEEK_SET, &seek);
			if(cellFsWrite(fd, dump, 0x40000, &nrw) != SUCCEEDED)
			{
				free_(dump);				
				cellFsClose(fd);
				cellFsUnlink(dump_file_path);
				showMessageRaw("An error occurred while dumping LV2", (char*)XAI_PLUGIN, (char*)TEX_ERROR);		

				return 1;
			}

			// Done dumping
			if(max_offset == final_offset)
				break;

			fseek_offset += 0x40000;
			memset(dump, 0, 0x40000);
			mem = 0;

			start_offset = start_offset + 0x40000;
			max_offset = max_offset + 0x40000;
		}
	}

	free_(dump);
	cellFsClose(fd);

	showMessageRaw(msgf("LV2 dumped in\n%s", dump_file_path), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	buzzer(SINGLE_BEEP);

	return 0;
}

void write_toggle(char* path_to_file, char* message)
{
	int fd = 0;
	cellFsOpen(path_to_file, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fd, 0, 0);
	cellFsClose(fd);
	showMessageRaw(msgf("%s", message), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void toggle_generic(char* path_to_file, char* name, int reverse_toggle)
{
	int ret = 0;
	int fd = 0;
	CellFsStat stat;
	ret = cellFsStat(path_to_file, &stat);
	if (ret != CELL_OK)
	{
		if (reverse_toggle == 0)
		{
			cellFsOpen(path_to_file, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fd, 0, 0);
			cellFsClose(fd);
			showMessageRaw(msgf("%s Disabled", name), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		}
		else
		{
			cellFsOpen(path_to_file, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fd, 0, 0);
			cellFsClose(fd);
			showMessageRaw(msgf("%s Enabled", name), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
		}
	}
	else
	{
		if (reverse_toggle == 0)
		{
			cellFsUnlink(path_to_file);
			showMessageRaw(msgf("%s Enabled", name), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
		}
		else
		{
			cellFsUnlink(path_to_file);
			showMessageRaw(msgf("%s Disabled", name), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		}
	}
}

void read_write_generic(const char* src, const char* dest)
{
	int ret, fda;
	ret = cellFsOpen(src, CELL_FS_O_RDONLY, &fda, 0, 0);

	if (ret != CELL_OK)
		showMessageRaw(msgf("%s Open Error: %x", src, ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else
	{
		int fdb = -1;
		ret = cellFsOpen(dest, CELL_FS_O_CREAT | CELL_FS_O_RDWR | CELL_FS_O_TRUNC, &fdb, 0, 0);

		//log("src: %s\n", (char*)src);
		//log("dest: %s\n", (char*)dest);

		if (ret != CELL_OK)
		{
			showMessageRaw(msgf("%s Open Error: %x", dest, ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			cellFsClose(fda);
			return;
		}

		uint8_t buf[0x1000];
		uint64_t nr, nrw;

		while ((ret = cellFsRead(fda, buf, 0x1000, &nr)) == CELL_FS_SUCCEEDED)
		{
			if ((int)nr > 0)
			{
				ret = cellFsWrite(fdb, buf, nr, &nrw);

				if (ret != CELL_FS_SUCCEEDED)
				{
					showMessageRaw(msgf("%s Copy Error: %x", src, ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
					cellFsClose(fda);
					cellFsClose(fdb);
					return;
				}

				memset(buf, 0, 0x1000);
			}
			else
				break;
		}

		cellFsChmod(dest, 0666);

		cellFsClose(fda);
		cellFsClose(fdb);

		//showMessage("%s created!", (char*)dest);
	}
}

void read_write_generic_notify(const char* src, const char* dest)
{
	int ret, fda;
	ret = cellFsOpen(src, CELL_FS_O_RDONLY, &fda, 0, 0);

	if (ret != CELL_OK)
		showMessageRaw(msgf("%s Open Error: %x", src, ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else
	{
		int fdb;
		ret = cellFsOpen(dest, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fdb, 0, 0);

		//log("src: %s\n", (char*)src);
		//log("dest: %s\n", (char*)dest);

		uint8_t buf[0x1000];
		uint64_t nr, nrw;

		while ((ret = cellFsRead(fda, buf, 0x1000, &nr)) == CELL_FS_SUCCEEDED)
		{
			if ((int)nr > 0)
			{
				ret = cellFsWrite(fdb, buf, nr, &nrw);

				if (ret != CELL_FS_SUCCEEDED)
				{
					showMessageRaw(msgf("%s Copy Error: %x", src, ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
					return;
				}

				memset(buf, 0, 0x1000);
			}
			else
				break;
		}

		cellFsChmod(dest, 0666);

		cellFsClose(fda);
		cellFsClose(fdb);

		showMessageRaw(msgf("%s created!", (char*)dest), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
	}
}

void read_write_generic2(const char* src, const char* dest, CellFsMode chmod)
{
	int ret, fda;
	ret = cellFsOpen(src, CELL_FS_O_RDONLY, &fda, 0, 0);

	if (ret != CELL_OK)
		showMessageRaw(msgf("%s Open Error: %x", src, ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
	else
	{
		int fdb;
		ret = cellFsOpen(dest, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fdb, 0, 0);

		//log("src: %s\n", (char*)src);
		//log("dest: %s\n", (char*)dest);

		uint8_t buf[0x1000];
		uint64_t nr, nrw;

		while ((ret = cellFsRead(fda, buf, 0x1000, &nr)) == CELL_FS_SUCCEEDED)
		{
			if ((int)nr > 0)
			{
				ret = cellFsWrite(fdb, buf, nr, &nrw);

				if (ret != CELL_FS_SUCCEEDED)
				{
					showMessageRaw(msgf("%s Copy Error: %x", src, ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
					return;
				}

				memset(buf, 0, 0x1000);
			}
			else
				break;
		}

		cellFsChmod(dest, chmod);

		cellFsClose(fda);
		cellFsClose(fdb);

		//showMessageRaw(msgf("%s created!", (char*)dest)), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
	}
}

void remove_directory(char*src)
{
	int fd;
	int ret;
	char *list = (char*)malloc_(1024);
	if (!list)
		return;

	ret = cellFsOpendir(src, &fd);
	if (ret != CELL_FS_SUCCEEDED)
	{
		free_(list);
		return;
	}
	//log("cellFsOpendir(%s, &fd) = %x\n", (char*)src, (char*)ret);

	CellFsDirent dirent;
	uint64_t n;
	while ((ret = cellFsReaddir(fd, &dirent, &n)) == CELL_FS_SUCCEEDED && n > 0)
	{
		if (dirent.d_namlen >= sizeof(dirent.d_name))
			dirent.d_namlen = sizeof(dirent.d_name) - 1;
		dirent.d_name[dirent.d_namlen] = 0;

		//log("cellFsReaddir(fd, &dirent, &n) = %x -> ", ret);
		//log(dirent.d_name); log("\n");

		if (CELL_FS_TYPE_DIRECTORY != dirent.d_type)
		{
			if ((strlen(src) + 1 + strlen(dirent.d_name) + 1) >= 1024)
				continue;

			vsh_sprintf(list, "%s/%s", src, dirent.d_name);
			//log("Fileout: %s\n", list);

			// Delete file
			ret = cellFsUnlink(list);
			//log("cellFsUnlink(%s) = %x\n", (char*)list, (char*)ret);
		}
		else if (strcmp(dirent.d_name, ".") != 0 && strcmp(dirent.d_name, "..") != 0)
		{
			if ((strlen(src) + 1 + strlen(dirent.d_name) + 1) >= 1024)
				continue;

			vsh_sprintf(list, "%s/%s", src, dirent.d_name);
			//log("Dirout: %s\n", list);

			// Recursively delete subdirectory
			remove_directory(list);

			// Delete empty subdirectory
			ret = cellFsRmdir(list);
			//log("cellFsRmdir(%s) = %x\n", (char*)list, (char*)ret);
		}
	}

	ret = cellFsClosedir(fd);
	//log("cellFsClosedir(fd) = %x\n", ret);

	free_(list);
}

/*
void remove_directory_bug(char*_src)
{
	int fd;
	int ret;
	char list[1024];
	char src[1024];
	vsh_sprintf(src, "/dev_hdd0/theme/../..%s", _src);// Insert recursive bug in path
	ret = cellFsOpendir(src, &fd);
	log("cellFsOpendir(%s, &fd) = %x\n", (char*)src, (char*)ret);

	CellFsDirent dirent;
	uint64_t n;
	while ((ret = cellFsReaddir(fd, &dirent, &n)) == CELL_FS_SUCCEEDED && n > 0)
	{
		log("cellFsReaddir(fd, &dirent, &n) = %x -> ", ret);
		log(dirent.d_name); log("\n");

		if (CELL_FS_TYPE_DIRECTORY != dirent.d_type)
		{
			vsh_sprintf(list, "%s/%s", src, dirent.d_name);
			log("Fileout: %s\n", list);

			// Delete file
			ret = cellFsUnlink(list);
			log("cellFsUnlink(%s) = %x\n", (char*)list, (char*)ret);
		}
		else if (strcmp(dirent.d_name, ".") != 0 && strcmp(dirent.d_name, "..") != 0)
		{
			vsh_sprintf(list, "%s/%s", src, dirent.d_name);
			log("Dirout: %s\n", list);

			// Recursively delete subdirectory
			remove_directory(list);

			// Delete empty subdirectory
			ret = cellFsRmdir(list);
			log("cellFsRmdir(%s) = %x\n", (char*)list, (char*)ret);
		}
	}

	ret = cellFsClosedir(fd);
	log("cellFsClosedir(fd) = %x\n", ret);
}
*/

void remove_file(char* path_to_file, char* message)
{
	cellFsUnlink(path_to_file);
	showMessageRaw(msgf("Removed: %s.\n%s", path_to_file, message), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void uninstall_hen()
{
	int ret = 0;
	CellFsStat stat;
	
	// Restore OFW Files
	const char* src_paths[] = {
		"/dev_hdd0/hen/restore/coldboot.raf",
		"/dev_hdd0/hen/restore/explore_plugin_full.rco",
		"/dev_hdd0/hen/restore/software_update_plugin.rco",
		"/dev_hdd0/hen/restore/category_game.xml",
		"/dev_hdd0/hen/restore/category_game_tool2.xml",
		"/dev_hdd0/hen/restore/category_network.xml",
		"/dev_hdd0/hen/restore/category_network_tool2.xml",
		"/dev_hdd0/hen/restore/category_psn.xml",
		"/dev_hdd0/hen/restore/category_video.xml",
		"/dev_hdd0/hen/restore/download_list.xml",
		"/dev_hdd0/hen/restore/registory.xml"
	};

	const char* dest_paths[] = {
		"/dev_rewrite/vsh/resource/coldboot.raf",
		"/dev_rewrite/vsh/resource/explore_plugin_full.rco",
		"/dev_rewrite/vsh/resource/software_update_plugin.rco",
		"/dev_rewrite/vsh/resource/explore/xmb/category_game.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_game_tool2.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_network.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_network_tool2.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_psn.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_video.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/download_list.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/registory.xml"
	};

	for (int i = 0; i < sizeof(src_paths) / sizeof(src_paths[0]); i++) {
		CellFsStat stat;
		if (cellFsStat(src_paths[i], &stat) != CELL_FS_SUCCEEDED) {
			// Source file does not exist
			continue;
		}
		cellFsUnlink(dest_paths[i]);
		sys_timer_usleep(100000);
		read_write_generic(src_paths[i], dest_paths[i]);
	}

	// Remove HEN Files in Flash
	const char* flash_files[] = {
		"/dev_rewrite/vsh/resource/explore/icon/hen_boot.png",
		"/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png",
		"/dev_rewrite/vsh/resource/explore/icon/hen_enable.png",
		"/dev_rewrite/vsh/resource/explore/icon/hen_repair.png",
		"/dev_rewrite/vsh/resource/videodownloader_plugin.rco",
		"/dev_rewrite/vsh/resource/videorec.rco",
		"/dev_rewrite/vsh/resource/xai_plugin.rco",
		"/dev_rewrite/vsh/module/videodownloader_plugin.sprx",
		"/dev_rewrite/vsh/module/videorec.sprx",
		"/dev_rewrite/vsh/module/xai_plugin.sprx"
	};
	for (int i = 0; i < sizeof(flash_files) / sizeof(flash_files[0]); i++) {
		ret = cellFsUnlink(flash_files[i]);
		if (ret != CELL_FS_SUCCEEDED) {
			showMessageRaw(msgf("Unlink Error: %x", ret), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		}
	}
	
	sys_timer_usleep(2000000);

	// Remove HEN Directories
	remove_directory("/dev_hdd0/theme/../../dev_hdd0/hen");
	remove_directory("/dev_hdd0/theme/../../dev_hdd0/game/PS3XPLOIT");
	remove_directory("/dev_hdd0/theme/../../dev_rewrite/hen");
	cellFsRmdir("/dev_hdd0/hen");
	cellFsRmdir("/dev_hdd0/game/PS3XPLOIT");
	cellFsRmdir("/dev_rewrite/hen");
	
	sys_timer_usleep(1000000);
	
	showMessageRaw("PS3HEN has been removed.\nSystem will now reboot back into HFW...", (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	sys_timer_usleep(5000000);

	rebootXMB(SYS_SOFT_REBOOT);
}

int switch_hen_mode(int mode)
{
	/*
	0 = Release
	1 = Debug
	2 = USB 000
	3 = USB 001
	*/

	switch (mode)
	{
		case 0:
			showMessageRaw("Switching To RELEASE Mode.\nPlease Wait...", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
			read_write_generic("/dev_hdd0/hen/mode/release/coldboot.raf", "/dev_rewrite/vsh/resource/coldboot.raf");
			read_write_generic("/dev_hdd0/hen/mode/release/hen_enable.png", "/dev_rewrite/vsh/resource/explore/icon/hen_enable.png");
			read_write_generic("/dev_hdd0/hen/mode/release/hen_disabled.png", "/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png");
			read_write_generic("/dev_hdd0/hen/mode/release/PS3HEN.BIN", "/dev_rewrite/hen/PS3HEN.BIN");
			read_write_generic("/dev_hdd0/hen/mode/release/ps3hen_updater.xml", "/dev_rewrite/hen/xml/ps3hen_updater.xml");
			showMessageRaw("Please reboot to activate RELEASE mode!", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
			break;
		case 1:
			showMessageRaw("Switching To DEBUG Mode.\nPlease Wait...", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
			read_write_generic("/dev_hdd0/hen/mode/debug/coldboot.raf", "/dev_rewrite/vsh/resource/coldboot.raf");
			read_write_generic("/dev_hdd0/hen/mode/debug/hen_enable.png", "/dev_rewrite/vsh/resource/explore/icon/hen_enable.png");
			read_write_generic("/dev_hdd0/hen/mode/debug/hen_disabled.png", "/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png");
			read_write_generic("/dev_hdd0/hen/mode/debug/PS3HEN.BIN", "/dev_rewrite/hen/PS3HEN.BIN");
			read_write_generic("/dev_hdd0/hen/mode/debug/ps3hen_updater.xml", "/dev_rewrite/hen/xml/ps3hen_updater.xml");
			showMessageRaw("Please reboot to activate DEBUG mode!", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
			break;
		case 2:
			showMessageRaw("Switching To USB000 Mode.\nPlease Wait...", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
			read_write_generic("/dev_hdd0/hen/mode/usb/coldboot.raf", "/dev_rewrite/vsh/resource/coldboot.raf");
			read_write_generic("/dev_hdd0/hen/mode/usb/hen_enable.png", "/dev_rewrite/vsh/resource/explore/icon/hen_enable.png");
			read_write_generic("/dev_hdd0/hen/mode/usb/hen_disabled.png", "/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png");
			read_write_generic("/dev_hdd0/hen/mode/usb/000/hen_enable.xml", "/dev_hdd0/hen/xml/hen_enable.xml");
			showMessageRaw("Please reboot to activate USB000 mode!", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
			break;
		case 3:
			showMessageRaw("Switching To USB001 Mode.\nPlease Wait...", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
			read_write_generic("/dev_hdd0/hen/mode/usb/coldboot.raf", "/dev_rewrite/vsh/resource/coldboot.raf");
			read_write_generic("/dev_hdd0/hen/mode/usb/hen_enable.png", "/dev_rewrite/vsh/resource/explore/icon/hen_enable.png");
			read_write_generic("/dev_hdd0/hen/mode/usb/hen_disabled.png", "/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png");
			read_write_generic("/dev_hdd0/hen/mode/usb/001/hen_enable.xml", "/dev_hdd0/hen/xml/hen_enable.xml");
			showMessageRaw("Please reboot to activate USB001 mode!", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
			break;
		default:
			break;
	}

}

// HFW XML Entries
void toggle_auto_update()
{
	toggle_generic("/dev_hdd0/hen_updater.off", "HEN Auto Update", 0);// Legacy Path 3.1.1 and lower
	//toggle_generic("/dev_hdd0/hen/toggles/hen_updater.off", "HEN Auto Update", 0);// New Path 3.2.0+
}

void toggle_hen_repair()
{
	toggle_generic("/dev_hdd0/hen/toggles/hen_repair.off", "HEN Repair", 0);
}

void toggle_patch_libaudio()
{
	toggle_generic("/dev_hdd0/hen/toggles/patch_libaudio.on", "libaudio Patch", 1);
}

// Clear Web Cache Functions (History, Auth Cache, Cookie)
void toggle_clear_web_history()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_web_history.on", "Clear Web Cache: History", 1);
}

void toggle_clear_web_auth_cache()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_web_auth_cache.on", "Clear Web Cache: Auth Cache", 1);
}

void toggle_clear_web_cookie()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_web_cookie.on", "Clear Web Cache: Cookie", 1);
}

void toggle_clear_psn_ci()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_ci.on", "Clear PSN Cache: CI.TMP", 1);
}

void toggle_clear_psn_mi()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_mi.on", "Clear PSN Cache: MI.TMP", 1);
}

void toggle_clear_psn_ptl()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_ptl.on", "Clear PSN Cache: PTL.TMP", 1);
}

void toggle_hen_dev_build()
{
	toggle_generic("/dev_hdd0/hen/toggles/dev_build_type.on", "Development Build Type", 1);
}

void disable_remaps_on_next_boot()
{
	write_toggle("/dev_hdd0/hen/toggles/remap_files.off", "MapPath Remappings Will Be Disabled On Next Boot");
}

void toggle_rap_bin()
{
	toggle_generic("/dev_hdd0/hen/toggles/rap_bin.on", "Reading from rap.bin", 1);
}

void toggle_hotkey_polling()
{
	toggle_generic("/dev_hdd0/hen/toggles/hotkey_polling.off", "HotKey Polling at Launch", 0);
}

void toggle_app_home()
{
	toggle_generic("/dev_hdd0/hen/toggles/app_home.on", "app_home Support", 1);
	sys_timer_usleep(100000);
	CellFsStat stat;
	if (cellFsStat("/dev_hdd0/hen/toggles/app_home.on", &stat) == CELL_OK)
	{
		cellFsUnlink("/dev_rewrite/vsh/resource/explore/xmb/category_game.xml");
		//cellFsUnlink("/dev_rewrite/vsh/module/explore_plugin.sprx");
		read_write_generic2("/dev_hdd0/hen/toggles/app_home/on/category_game.xml", "/dev_rewrite/vsh/resource/explore/xmb/category_game.xml", 0600);
		//read_write_generic2("/dev_hdd0/hen/toggles/app_home/on/explore_plugin.sprx", "/dev_rewrite/vsh/module/explore_plugin.sprx", 0644);
		showMessageRaw("app_home Enabled.\nRefresh XMB or Reboot.", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
	}
	else
	{
		cellFsUnlink("/dev_rewrite/vsh/resource/explore/xmb/category_game.xml");
		//cellFsUnlink("/dev_rewrite/vsh/module/explore_plugin.sprx");
		read_write_generic2("/dev_hdd0/hen/toggles/app_home/off/category_game.xml", "/dev_rewrite/vsh/resource/explore/xmb/category_game.xml", 0600);
		//read_write_generic2("/dev_hdd0/hen/toggles/app_home/off/explore_plugin.sprx", "/dev_rewrite/vsh/module/explore_plugin.sprx", 0644);
		showMessageRaw("app_home Disabled.\nRefresh XMB or Reboot.", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
	}
}

void toggle_quick_preview()
{
	toggle_generic("/dev_hdd0/hen/toggles/quick_preview.on", "Quick Preview Support", 1);
	sys_timer_usleep(100000);
	CellFsStat stat;
	if (cellFsStat("/dev_hdd0/hen/toggles/quick_preview.on", &stat) == CELL_OK)
	{
		cellFsUnlink("/dev_rewrite/vsh/module/explore_plugin.sprx");
		read_write_generic2("/dev_hdd0/hen/toggles/quick_preview/on/explore_plugin.sprx", "/dev_rewrite/vsh/module/explore_plugin.sprx", 0644);
		showMessageRaw("Quick Preview Enabled\nexplore_plugin.sprx will have visual artifacts on 4.89+\nRefresh XMB or Reboot.", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
	}
	else
	{
		cellFsUnlink("/dev_rewrite/vsh/module/explore_plugin.sprx");
		read_write_generic2("/dev_hdd0/hen/toggles/quick_preview/off/explore_plugin.sprx", "/dev_rewrite/vsh/module/explore_plugin.sprx", 0644);
		showMessageRaw("Quick Preview Disabled\nOriginal explore_plugin.sprx copied\nRefresh XMB or Reboot.", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
	}
}
