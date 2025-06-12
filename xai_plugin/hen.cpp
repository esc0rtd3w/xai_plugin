#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
//#include <sys/fs_external.h>
#include <sys/timer.h>
#include "hen.h"
#include "functions.h"
#include "gccpch.h"
#include "log.h"
#include "hfw_settings.h"

/*uint64_t peekq(uint64_t addr) // peekq(0x80000000002E9D70ULL)==0x4345580000000000ULL
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
	//peekq(paddr);
	showMessageRaw(msgf("peekq %08X: Old Bytes %08X\n", kaddr, peekq(kaddr), 0, 0, false), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	pokeq(kaddr, kbytes);

	//peekq(paddr);
	showMessageRaw(msgf("peekq %08X: New Bytes %08X\n", kaddr, peekq(kaddr), 0, 0, false), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}*/

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
			showMessageRaw(msgf("%s Disabled", name), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
		}
		else
		{
			cellFsOpen(path_to_file, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fd, 0, 0);
			cellFsClose(fd);
			showMessageRaw(msgf("%s Enabled", name), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
		}
	}
	else
	{
		if (reverse_toggle == 0)
		{
			cellFsUnlink(path_to_file);
			showMessageRaw(msgf("%s Enabled", name), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
		}
		else
		{
			cellFsUnlink(path_to_file);
			showMessageRaw(msgf("%s Disabled", name), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
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

		//showMessageRaw(msgf("%s created!", (char*)dest), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
	}
}

void remove_directory(char*src)
{
	int fd;
	int ret;
	char list[1024];
	ret = cellFsOpendir(src, &fd);
	//log("cellFsOpendir(%s, &fd) = %x\n", (char*)src, (char*)ret);

	CellFsDirent dirent;
	uint64_t n;
	while ((ret = cellFsReaddir(fd, &dirent, &n)) == CELL_FS_SUCCEEDED && n > 0)
	{
		//log("cellFsReaddir(fd, &dirent, &n) = %x -> ", ret);
		//log(dirent.d_name); log("\n");

		if (CELL_FS_TYPE_DIRECTORY != dirent.d_type)
		{
			vsh_sprintf(list, "%s/%s", src, dirent.d_name);
			//log("Fileout: %s\n", list);

			// Delete file
			ret = cellFsUnlink(list);
			//log("cellFsUnlink(%s) = %x\n", (char*)list, (char*)ret);
		}
		else if (strcmp(dirent.d_name, ".") != 0 && strcmp(dirent.d_name, "..") != 0)
		{
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

