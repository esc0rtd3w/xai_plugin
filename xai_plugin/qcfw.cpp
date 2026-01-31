#include <string.h>
#include <cell/fs/cell_fs_file_api.h>

#include "functions.h"
#include "hfw_settings.h"
#include "log.h"

int32_t qcfw_hvcall_114(uint64_t phys_addr, uint64_t page_size, uint64_t size, uint64_t* out_lpar_addr)
{
	system_call_8(10, phys_addr, page_size, size, 0, 0, 0, 0, 114);

	if (out_lpar_addr != NULL)
		*out_lpar_addr = p2;

	return_to_user_prog(int32_t);
}

int32_t qcfw_hvcall_115(uint64_t lpar_addr)
{
	system_call_8(10, lpar_addr, 0, 0, 0, 0, 0, 0, 115);
	return_to_user_prog(int32_t);
}

bool qcfw_is_exploited()
{
	uint64_t lpar_addr = 0;

	int32_t res = qcfw_hvcall_114(0, 12, 4096, &lpar_addr);
	if (res != 0)
		return false;

	res = qcfw_hvcall_115(lpar_addr);
	if (res != 0)
		return false;

	return true;
}

bool qcfw_is_nor()
{
	uint8_t flag;

	int32_t res = lv2_ss_get_cache_of_flash_ext_flag(&flag);
	if (res != 0)
		return false;

	return !(flag & 0x1);
}

bool qcfw_sc_read_shadow_os_bank_indicator(uint8_t* outValue)
{
	return update_mgr_read_eeprom(0x3001, outValue) == 0;
}

bool qcfw_sc_write_request_os_bank_indicator(uint8_t value)
{
	return update_mgr_write_eeprom(0x3002, value) == 0;
}

bool qcfw_read_from_file(const char* path, void* outBuf, uint64_t offset, uint32_t readSize)
{
	int32_t fd;

	if (cellFsOpen(path, CELL_FS_O_RDONLY, &fd, 0, 0) != CELL_FS_SUCCEEDED)
		return false;

	bool result = true;

	uint64_t junk;
	result = (cellFsLseek(fd, offset, SEEK_SET, &junk) == CELL_FS_SUCCEEDED);

	if (result && (readSize > 0))
	{
		uint64_t readSuccessSize = 0;
		cellFsRead(fd, outBuf, readSize, &readSuccessSize);

		if (readSuccessSize != readSize)
			result = false;
	}

	cellFsClose(fd);
	return result;
}

// initial crc should be 0
uint32_t qcfw_crc32c(uint32_t crc, const uint8_t* buf, size_t len)
{
	int32_t k;

	crc = ~crc;
	while (len--) {
		crc ^= *buf++;
		for (k = 0; k < 8; k++)
			crc = crc & 1 ? (crc >> 1) ^ 0xedb88320 : crc >> 1;
	}
	return ~crc;
}

bool qcfw_calc_crc32(const char* filePath, uint32_t* outCrc32)
{
	CellFsStat file_Stat;
	if (cellFsStat(filePath, &file_Stat) != CELL_FS_SUCCEEDED)
		return false;

	if ((file_Stat.st_size == 0) || (file_Stat.st_size > 0x10000000))
		return false;

	static const uint32_t tmpDataBuf_MaxSize = (256 * 1024); // careful!
	uint8_t* tmpDataBuf = (uint8_t*)malloc__(tmpDataBuf_MaxSize);

	if (tmpDataBuf == NULL)
		return false;

	bool result = true;

	uint32_t crc32 = 0;

	{
		uint32_t curFileOffset = 0;
		uint32_t left = (uint32_t)file_Stat.st_size;

		while (1)
		{
			uint32_t processSize = (left > tmpDataBuf_MaxSize) ? tmpDataBuf_MaxSize : left;

			if (!qcfw_read_from_file(filePath, tmpDataBuf, curFileOffset, processSize))
			{
				result = false;
				break;
			}

			crc32 = qcfw_crc32c(crc32, tmpDataBuf, processSize);

			curFileOffset += processSize;
			left -= processSize;

			if (left == 0)
				break;
		}
	}

	free__(tmpDataBuf);
	tmpDataBuf = NULL;

	if (outCrc32 != NULL)
		*outCrc32 = crc32;

	return result;
}

bool qcfw_get_qcfw_crc32(const char* crc32FilePath, uint32_t* outStagexCrc32, uint32_t* outStagexAuxCrc32, uint32_t* outCoreOSCrc32)
{
	CellFsStat crc32File_Stat;
	if (cellFsStat(crc32FilePath, &crc32File_Stat) != CELL_FS_SUCCEEDED)
		return false;

	if (crc32File_Stat.st_size != 12)
		return false;

	uint32_t crc32s[3];
	crc32s[0] = 0;
	crc32s[1] = 0;
	crc32s[2] = 0;

	if (!qcfw_read_from_file(crc32FilePath, crc32s, 0, 12))
		return false;

	if (crc32s[0] == 0)
		return false;

	if (crc32s[1] == 0)
		return false;

	if (crc32s[2] == 0)
		return false;

	if (outStagexCrc32 != NULL)
		*outStagexCrc32 = crc32s[0];

	if (outStagexAuxCrc32 != NULL)
		*outStagexAuxCrc32 = crc32s[1];

	if (outCoreOSCrc32 != NULL)
		*outCoreOSCrc32 = crc32s[2];

	return true;
}

bool qcfw_nor_write(uint64_t offset, const void* data, uint32_t size)
{
	const uint8_t* dataa = (const uint8_t*)data;

	if (data == NULL)
		return false;

	if (size == 0)
		return true;

	if (!qcfw_is_nor())
		return false;

	int32_t res;

	uint32_t unknown2;

	uint64_t dev_id = 0x100000000000004ull;
	uint64_t dev_flags = 0x22ull;

	static const uint32_t sector_size = 512;
	uint32_t burst_size = (512 * sector_size);

	uint32_t dev_handle;

	res = lv2_storage_open(dev_id, &dev_handle);
	if (res != 0)
		return false;

	uint8_t* buf = (uint8_t*)malloc__(burst_size);

	if (buf == NULL)
	{
		lv2_storage_close(dev_handle);
		return false;
	}

	uint32_t curOffset = offset;
	uint32_t curDataOffset = 0;

	uint32_t left = size;

	while (left > 0)
	{
		uint32_t processSize = (left > sector_size) ? sector_size : left;
		uint32_t zzz = (curOffset % sector_size);
		uint32_t yyy = (sector_size - zzz);
		uint32_t xxx = (yyy > processSize) ? processSize : yyy;

		uint32_t sector_idx = (curOffset / sector_size);

		if (burst_size > left)
		{
			while (burst_size > left)
				burst_size -= sector_size;
		}

		if ((zzz != 0) || (processSize != sector_size))
		{
			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				free__(buf);
				return false;
			}

			memcpy(&buf[zzz], &dataa[curDataOffset], xxx);

			res = lv2_storage_write(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				free__(buf);
				return false;
			}

			curOffset += xxx;
			curDataOffset += xxx;

			left -= xxx;
		}
		else if ((burst_size > 0) && (left >= burst_size) && ((burst_size % sector_size) == 0))
		{
			memcpy(&buf[0], &dataa[curDataOffset], burst_size);

			res = lv2_storage_write(dev_handle, 0, sector_idx, (burst_size / sector_size), buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				free__(buf);
				return false;
			}

			curOffset += burst_size;
			curDataOffset += burst_size;

			left -= burst_size;
		}
		else
		{
			memcpy(&buf[0], &dataa[curDataOffset], processSize);

			res = lv2_storage_write(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				free__(buf);
				return false;
			}

			curOffset += processSize;
			curDataOffset += processSize;

			left -= processSize;
		}
	}

	res = lv2_storage_close(dev_handle);
	if (res != 0)
		return false;

	free__(buf);
	return true;
}

bool qcfw_install_stagex(bool showSuccess)
{
	if (!qcfw_is_nor())
	{
		PrintString(L"Flash is not NOR!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	const char* stagex_path = "/dev_usb000/qcfw/Stagex.bin";
	bool stagex_exist = false;
	CellFsStat stagex_stat;
	stagex_exist = (cellFsStat(stagex_path, &stagex_stat) == CELL_FS_SUCCEEDED);

	const char* stagex_aux_path = "/dev_usb000/qcfw/Stagex_aux.bin";
	bool stagex_aux_exist = false;
	CellFsStat stagex_aux_stat;
	stagex_aux_exist = (cellFsStat(stagex_aux_path, &stagex_aux_stat) == CELL_FS_SUCCEEDED);

	if (!stagex_exist || !stagex_aux_exist)
	{
		PrintString(L"File not found!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	// important!!!
	if (
		(stagex_stat.st_size == 0) || (stagex_stat.st_size > (0xC000)) || // 48kb
		(stagex_aux_stat.st_size == 0) || (stagex_aux_stat.st_size > (0x18000)) // 96kb
	)
	{
		PrintString(L"Bad file size!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	uint32_t stagex_crc32 = 0;
	if (!qcfw_calc_crc32(stagex_path, &stagex_crc32) || (stagex_crc32 == 0))
	{
		PrintString(L"Stagex CRC32 calc failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	uint32_t stagex_aux_crc32 = 0;
	if (!qcfw_calc_crc32(stagex_aux_path, &stagex_aux_crc32) || (stagex_aux_crc32 == 0))
	{
		PrintString(L"Stagex_aux CRC32 calc failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	uint32_t expected_stagex_crc32 = 0;
	uint32_t expected_stagex_aux_crc32 = 0;
	if (!qcfw_get_qcfw_crc32("/dev_usb000/qcfw/qcfw.crc32", &expected_stagex_crc32, &expected_stagex_aux_crc32, NULL) || (expected_stagex_crc32 == 0) || (expected_stagex_aux_crc32 == 0))
	{
		PrintString(L"qcfw CRC32 get failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (stagex_crc32 != expected_stagex_crc32)
	{
		PrintString(L"Stagex CRC32 check failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (stagex_aux_crc32 != expected_stagex_aux_crc32)
	{
		PrintString(L"Stagex_aux CRC32 check failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	static const uint32_t tmpDataBuf_MaxSize = (128 * 1024); // careful!
	uint8_t* tmpDataBuf = (uint8_t*)malloc__(tmpDataBuf_MaxSize);

	if (tmpDataBuf == NULL)
		return false;

	//

	if (!qcfw_read_from_file(stagex_path, tmpDataBuf, 0, (uint32_t)stagex_stat.st_size))
	{
		free__(tmpDataBuf);
		tmpDataBuf = NULL;

		PrintString(L"File read failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (!qcfw_nor_write(0x31000, tmpDataBuf, (uint32_t)stagex_stat.st_size)) // careful!
	{
		free__(tmpDataBuf);
		tmpDataBuf = NULL;

		PrintString(L"NorWrite failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	//

	if (!qcfw_read_from_file(stagex_aux_path, tmpDataBuf, 0, (uint32_t)stagex_aux_stat.st_size))
	{
		free__(tmpDataBuf);
		tmpDataBuf = NULL;

		PrintString(L"File read failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (!qcfw_nor_write(0xF21000, tmpDataBuf, (uint32_t)stagex_aux_stat.st_size)) // careful!
	{
		free__(tmpDataBuf);
		tmpDataBuf = NULL;

		PrintString(L"NorWrite failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	//

	free__(tmpDataBuf);
	tmpDataBuf = NULL;

	if (showSuccess)
		PrintString(L"Success!", XAI_PLUGIN, TEX_SUCCESS);

	return true;
}

bool qcfw_rmdir(const char* dirPath)
{
	int dir_fd;

	if (cellFsOpendir(dirPath, &dir_fd) != CELL_FS_SUCCEEDED)
		return false;

	CellFsDirent dirent;
	uint64_t read;

	bool result = true;

	while (cellFsReaddir(dir_fd, &dirent, &read) == CELL_FS_SUCCEEDED)
	{
		if (read == 0)
			break;

		if (!strcmp(dirent.d_name, ".") || !strcmp(dirent.d_name, ".."))
			continue;

		if (dirent.d_type == CELL_FS_TYPE_DIRECTORY)
		{
			static const uint32_t fullPath_MaxSize = 1024;
			char* fullPath = (char*)malloc__(fullPath_MaxSize);

			if (fullPath == NULL)
			{
				result = false;
				break;
			}

			sprintf_(fullPath, "%s/%s", (int)dirPath, (int)dirent.d_name);
			result = qcfw_rmdir(fullPath);
			free__(fullPath);

			if (!result)
				break;

			continue;
		}

		if (dirent.d_type != CELL_FS_TYPE_REGULAR)
			continue;

		static const uint32_t fullPath_MaxSize = 1024;
		char* fullPath = (char*)malloc__(fullPath_MaxSize);

		if (fullPath == NULL)
		{
			result = false;
			break;
		}

		sprintf_(fullPath, "%s/%s", (int)dirPath, (int)dirent.d_name);
		cellFsUnlink(fullPath); // result?
		free__(fullPath);
	}

	cellFsClosedir(dir_fd);

	cellFsRmdir(dirPath);  // result?
	return result;
}

bool qcfw_cpdir(const char* srcDirPath, const char* destDirPath)
{
	int dir_fd;

	if (cellFsOpendir(srcDirPath, &dir_fd) != CELL_FS_SUCCEEDED)
		return false;

	cellFsMkdir(destDirPath, 0777);

	CellFsDirent dirent;
	uint64_t read;

	bool result = true;

	while (cellFsReaddir(dir_fd, &dirent, &read) == CELL_FS_SUCCEEDED)
	{
		if (read == 0)
			break;

		if (!strcmp(dirent.d_name, ".") || !strcmp(dirent.d_name, ".."))
			continue;

		if (dirent.d_type == CELL_FS_TYPE_DIRECTORY)
		{
			// Try to skip apple stuff

			if (!strcmp(dirent.d_name, ".Spotlight-V100"))
				continue;

			if (!strcmp(dirent.d_name, ".Trashes"))
				continue;

			if (!strcmp(dirent.d_name, ".fseventsd"))
				continue;

			static const uint32_t srcFullPath_MaxSize = 1024;
			char* srcFullPath = (char*)malloc__(srcFullPath_MaxSize);

			if (srcFullPath == NULL)
			{
				result = false;
				break;
			}

			static const uint32_t destFullPath_MaxSize = 1024;
			char* destFullPath = (char*)malloc__(destFullPath_MaxSize);

			if (destFullPath == NULL)
			{
				free__(srcFullPath);

				result = false;
				break;
			}

			sprintf_(srcFullPath, "%s/%s", (int)srcDirPath, (int)dirent.d_name);
			sprintf_(destFullPath, "%s/%s", (int)destDirPath, (int)dirent.d_name);

			cellFsMkdir(destFullPath, 0777);
			result = qcfw_cpdir(srcFullPath, destFullPath);

			free__(destFullPath);
			free__(srcFullPath);

			if (!result)
				break;

			continue;
		}

		if (dirent.d_type != CELL_FS_TYPE_REGULAR)
			continue;

		// Try to skip apple stuff
		if ((dirent.d_name[0] == '.') && (dirent.d_name[1] == '_'))
			continue;

		static const uint32_t srcFullPath_MaxSize = 1024;
		char* srcFullPath = (char*)malloc__(srcFullPath_MaxSize);

		if (srcFullPath == NULL)
		{
			result = false;
			break;
		}

		static const uint32_t destFullPath_MaxSize = 1024;
		char* destFullPath = (char*)malloc__(destFullPath_MaxSize);

		if (destFullPath == NULL)
		{
			free__(srcFullPath);

			result = false;
			break;
		}

		sprintf_(srcFullPath, "%s/%s", (int)srcDirPath, (int)dirent.d_name);
		sprintf_(destFullPath, "%s/%s", (int)destDirPath, (int)dirent.d_name);

		cellFsUnlink(destFullPath);
		result = (filecopy(srcFullPath, destFullPath) == 0);

		free__(destFullPath);
		free__(srcFullPath);

		if (!result)
			break;
	}

	cellFsClosedir(dir_fd);
	return result;
}

bool qcfw_install_qcfw()
{
	if (!qcfw_is_exploited())
	{
		PrintString(L"Install Stagex and modchip first!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	uint8_t shadow_os_bank_indicator = 0xff;
	if (!qcfw_sc_read_shadow_os_bank_indicator(&shadow_os_bank_indicator))
		return false;

	if (shadow_os_bank_indicator != 0x2)
	{
		PrintString(L"Reinstall firmware then try again.", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	const char* coreos_path = "/dev_usb000/qcfw/CoreOS.bin";
	bool coreos_exist = false;
	CellFsStat coreos_stat;
	coreos_exist = (cellFsStat(coreos_path, &coreos_stat) == CELL_FS_SUCCEEDED);

	if (!coreos_exist)
	{
		PrintString(L"CoreOS.bin not found!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	// important!!!
	if (
		(coreos_stat.st_size == 0) || (coreos_stat.st_size > (0x700000))
	)
	{
		PrintString(L"Bad file size!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (!qcfw_install_stagex(false))
		return false;

	uint32_t coreos_crc32 = 0;
	if (!qcfw_calc_crc32(coreos_path, &coreos_crc32) || (coreos_crc32 == 0))
	{
		PrintString(L"CoreOS CRC32 calc failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	uint32_t expected_coreos_crc32 = 0;
	if (!qcfw_get_qcfw_crc32("/dev_usb000/qcfw/qcfw.crc32", NULL, NULL, &expected_coreos_crc32) || (expected_coreos_crc32 == 0))
	{
		PrintString(L"qcfw CRC32 get failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (coreos_crc32 != expected_coreos_crc32)
	{
		PrintString(L"CoreOS CRC32 check failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	static const uint32_t tmpDataBuf_MaxSize = (256 * 1024); // careful!
	uint8_t* tmpDataBuf = (uint8_t*)malloc__(tmpDataBuf_MaxSize);

	if (tmpDataBuf == NULL)
		return false;

	{
		uint32_t curFileOffset = 0;
		uint32_t left = (uint32_t)coreos_stat.st_size;

		while (1)
		{
			bool result = true;

			uint32_t processSize = (left > tmpDataBuf_MaxSize) ? tmpDataBuf_MaxSize : left;

			result = qcfw_read_from_file(coreos_path, tmpDataBuf, curFileOffset, processSize);
			if (result)
			{
				result = qcfw_nor_write(
					(0x0C0000 + curFileOffset), // careful!

					tmpDataBuf,
					processSize
				);
			}

			if (!result)
			{
				PrintString(L"Write failed!", XAI_PLUGIN, TEX_ERROR);

				free__(tmpDataBuf);
				tmpDataBuf = NULL;

				return false;
			}

			curFileOffset += processSize;
			left -= processSize;

			if (left == 0)
				break;
		}
	}

	// free right after done!
	free__(tmpDataBuf);
	tmpDataBuf = NULL;

	// only wipe and copy dev_blind if /dev_usb000/qcfw/dev_flash directory exists

	{
		const char* usb_dirPath = "/dev_usb000/qcfw/dev_flash";
		int32_t usb_fd;

		if (cellFsOpendir(usb_dirPath, &usb_fd) == CELL_FS_SUCCEEDED)
		{
			cellFsClosedir(usb_fd);

			mount_dev_blind();
			qcfw_rmdir("/dev_blind");

			if (!qcfw_cpdir(usb_dirPath, "/dev_blind"))
			{
				PrintString(L"Copy dev_flash failed!", XAI_PLUGIN, TEX_ERROR);
				return false;
			}
		}
	}

	if (!qcfw_sc_write_request_os_bank_indicator(0x1))
	{
		PrintString(L"Bank switch failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	rebootXMB(SYS_SOFT_REBOOT);
	return true;
}