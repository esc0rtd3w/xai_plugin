#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/timer.h>

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

int32_t qcfw_fs_sync(const char* path)
{
	system_call_1(839, (uint64_t)path);
	return_to_user_prog(int32_t);
}

int32_t qcfw_mount_dev_flash()
{
	system_call_8(837, (uint64_t)"CELL_FS_IOS:BUILTIN_FLSH1", (uint64_t)"CELL_FS_FAT", (uint64_t)"/dev_flash", 0, 1, 0, 0, 0);
	return_to_user_prog(int32_t);
}

int32_t qcfw_umount(const char* path)
{
	system_call_1(838, (uint64_t)path);
	return_to_user_prog(int32_t);
}

int32_t qcfw_newfs_dev_flash()
{
	system_call_4(836, (uint64_t)"CELL_FS_IOS:BUILTIN_FLSH1", (uint64_t)"CELL_FS_FAT", 0, 0);
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

uint64_t qcfw_emmc_get_sector_count()
{
	if (qcfw_is_nor())
		return 0;

	int32_t res;

	uint64_t dev_id = 0x100000000000001ull;

	struct storage_device_info info;
	res = lv2_storage_get_device_info(dev_id, &info);
	if (res != 0)
		return 0;

	if (info.sector_size != 512)
		return 0;

	// info.capacity =
	// 0x1892e00 (KLMAG2GE4A-A001)
	// 0x189ee00 (KLMAG2GEAC-B001)

	uint64_t result = (info.capacity + 0x200);
	if (result < 0x1000000)
		return 0;
	
	return result;
}

uint64_t qcfw_emmc_get_size()
{
	return (qcfw_emmc_get_sector_count() * 512);
}

bool qcfw_is_emmc()
{
	return (qcfw_emmc_get_size() > 0);
}

bool qcfw_sc_read_shadow_os_bank_indicator(uint8_t* outValue)
{
	return update_mgr_read_eeprom(0x3001, outValue) == 0;
}

bool qcfw_sc_write_request_os_bank_indicator(uint8_t value)
{
	return update_mgr_write_eeprom(0x3002, value) == 0;
}

bool qcfw_sc_write_ros0_crc32(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x3008 + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_ros1_crc32(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x300c + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_read_modchip_version(uint8_t* outValue)
{
	return update_mgr_read_eeprom(0x3010, outValue) == 0;
}

bool qcfw_sc_read_lv0ldr_region_dump_status(uint8_t* outValue)
{
	return update_mgr_read_eeprom(0x3013, outValue) == 0;
}

bool qcfw_sc_write_stagex_size(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30a0 + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_stagex_crc32(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30a4 + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_stagex_aux_size(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30a8 + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_stagex_aux_crc32(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30ac + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_stagex_size_bak(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30b0 + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_stagex_crc32_bak(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30b4 + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_stagex_aux_size_bak(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30b8 + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_stagex_aux_crc32_bak(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30bc + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_ros0_crc32_bak(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30c0 + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_write_ros1_crc32_bak(uint32_t value)
{
	const uint8_t* p = (const uint8_t*)&value;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_write_eeprom((0x30c4 + i), p[i]) != 0)
			return false;
	}

	return true;
}

bool qcfw_sc_read_lv0ldr_region_crc32(uint32_t* outValue)
{
	uint8_t* p = (uint8_t*)outValue;

	for (uint32_t i = 0; i < 4; ++i)
	{
		if (update_mgr_read_eeprom((0x30c8 + i), &p[i]) != 0)
			return false;
	}

	return true;
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

bool qcfw_calc_crc32_from_file(const char* filePath, uint32_t* outCrc32)
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

	if (crc32File_Stat.st_size != 15) // modchip v2
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

bool qcfw_nor_read(uint64_t offset, void* data, uint32_t size, uint32_t burst_size)
{
	uint8_t* dataa = (uint8_t*)data;

	if (data == NULL)
		return false;

	if (size == 0)
		return true;

	if ((offset + size) > (16 * 1024 * 1024))
		return false;

	if (!qcfw_is_nor())
		return false;

	int32_t res;

	uint32_t unknown2;

	uint64_t dev_id = 0x100000000000004ull;
	uint64_t dev_flags = 0x22ull;

	static const uint32_t sector_size = 512;

	if ((burst_size == 0) || ((burst_size % sector_size) != 0))
		return false;

	uint32_t dev_handle;

	res = lv2_storage_open(dev_id, &dev_handle);
	if (res != 0)
		return false;

	uint8_t buf[sector_size];

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

		while (burst_size > left)
			burst_size -= sector_size;

		if ((zzz != 0) || (processSize != sector_size))
		{
			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			memcpy(&dataa[curDataOffset], &buf[zzz], xxx);

			curOffset += xxx;
			curDataOffset += xxx;

			left -= xxx;
		}
		else if ((burst_size > 0) && (left >= burst_size) && ((burst_size % sector_size) == 0))
		{
			res = lv2_storage_read(dev_handle, 0, sector_idx, (burst_size / sector_size), &dataa[curDataOffset], &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			curOffset += burst_size;
			curDataOffset += burst_size;

			left -= burst_size;
		}
		else
		{
			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, &dataa[curDataOffset], &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
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

	return true;
}

bool qcfw_nor_write(uint64_t offset, const void* data, uint32_t size, uint32_t burst_size)
{
	const uint8_t* dataa = (const uint8_t*)data;

	if (data == NULL)
		return false;

	if (size == 0)
		return true;

	if ((offset + size) > (16 * 1024 * 1024))
		return false;

	if (!qcfw_is_nor())
		return false;

	int32_t res;

	uint32_t unknown2;

	uint64_t dev_id = 0x100000000000004ull;
	uint64_t dev_flags = 0x22ull;

	static const uint32_t sector_size = 512;

	if ((burst_size == 0) || ((burst_size % sector_size) != 0))
		return false;

	uint32_t dev_handle;

	res = lv2_storage_open(dev_id, &dev_handle);
	if (res != 0)
		return false;

	uint8_t buf[sector_size];

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

		while (burst_size > left)
			burst_size -= sector_size;

		if ((zzz != 0) || (processSize != sector_size))
		{
			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			memcpy(&buf[zzz], &dataa[curDataOffset], xxx);

			res = lv2_storage_write(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			curOffset += xxx;
			curDataOffset += xxx;

			left -= xxx;
		}
		else if ((burst_size > 0) && (left >= burst_size) && ((burst_size % sector_size) == 0))
		{
			res = lv2_storage_write(dev_handle, 0, sector_idx, (burst_size / sector_size), &dataa[curDataOffset], &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			curOffset += burst_size;
			curDataOffset += burst_size;

			left -= burst_size;
		}
		else
		{
			res = lv2_storage_write(dev_handle, 0, sector_idx, 1, &dataa[curDataOffset], &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
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

	return true;
}

bool qcfw_dump_nor_to_file(uint32_t offset, uint32_t size, const char* filePath, uint32_t chunk_size)
{
	if (chunk_size == 0)
		return false;

	uint8_t* chunkBuf = (uint8_t*)malloc__(chunk_size);
	if (chunkBuf == NULL)
		return false;

	int32_t fd;
	if (cellFsOpen(filePath, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != CELL_FS_SUCCEEDED)
	{
		free__(chunkBuf);
		return false;
	}

	cellFsChmod(filePath, 0777);

	{
		uint32_t left = size;
		uint32_t curNorOffset = offset;

		while (left > 0)
		{
			uint32_t processSize = (left > chunk_size) ? chunk_size : left;
			uint64_t writeSuccessSize = 0;

			if
			(
				!qcfw_nor_read(curNorOffset, chunkBuf, processSize, (256 * 1024)) ||
				(cellFsWrite(fd, chunkBuf, processSize, &writeSuccessSize) != CELL_FS_SUCCEEDED) ||
				(writeSuccessSize != processSize)
			)
			{
				cellFsClose(fd);
				free__(chunkBuf);

				return false;
			}

			curNorOffset += processSize;
			left -= processSize;
		}
	}

	cellFsClose(fd);
	free__(chunkBuf);

	return true;
}

bool qcfw_calc_crc32_from_nor(uint32_t offset, uint32_t size, uint32_t chunk_size, uint32_t* out_crc32)
{
	if (chunk_size == 0)
		return false;

	uint8_t* chunkBuf = (uint8_t*)malloc__(chunk_size);
	if (chunkBuf == NULL)
		return false;

	uint32_t crc32 = 0;

	{
		uint32_t left = size;
		uint32_t curNorOffset = offset;

		while (left > 0)
		{
			uint32_t processSize = (left > chunk_size) ? chunk_size : left;

			if (!qcfw_nor_read(curNorOffset, chunkBuf, processSize, (256 * 1024)))
			{
				free__(chunkBuf);
				return false;
			}

			crc32 = qcfw_crc32c(crc32, chunkBuf, processSize);

			curNorOffset += processSize;
			left -= processSize;
		}
	}

	if (out_crc32 != NULL)
		*out_crc32 = crc32;

	free__(chunkBuf);
	return true;
}

int32_t qcfw_lv2_storage_read_emmc(uint32_t dev_handle, uint64_t unknown1, uint64_t start_sector, uint64_t sector_count, void *buf, uint32_t *unknown2, uint64_t flags)
{
	if (!qcfw_is_emmc())
		return 1;

	if (sector_count == 0)
		return 0;

	if ((start_sector + sector_count) > qcfw_emmc_get_sector_count())
		return 1;

	static const uint32_t sector_size = 512;
	static const uint32_t masked_sector_count = (0x40000 / sector_size);

	if (start_sector < masked_sector_count)
	{
		uint8_t* buff = (uint8_t*)buf;

		uint32_t leftSectorCount = sector_count;
		uint32_t fillSectorCount = (masked_sector_count - start_sector);

		if (fillSectorCount > leftSectorCount)
			fillSectorCount = leftSectorCount;

		uint32_t totalSizeToFillInBytes = (fillSectorCount * sector_size);
		memset(buff, 0xff, totalSizeToFillInBytes);

		{
			int32_t res = lv2_storage_read(dev_handle, unknown1, ((start_sector + (0xF000000 / sector_size)) - masked_sector_count), fillSectorCount, &buff[0], unknown2, flags);

			if (res != 0)
				return res;
		}

		leftSectorCount -= fillSectorCount;

		if (leftSectorCount > 0)
			return lv2_storage_read(dev_handle, unknown1, 0, leftSectorCount, &buff[totalSizeToFillInBytes], unknown2, flags);
		
		return 0;
	}

	return lv2_storage_read(dev_handle, unknown1, (start_sector - masked_sector_count), sector_count, buf, unknown2, flags);
}

int32_t qcfw_lv2_storage_write_emmc(uint32_t dev_handle, uint64_t unknown1, uint64_t start_sector, uint64_t sector_count, const void *buf, uint32_t *unknown2, uint64_t flags)
{
	if (!qcfw_is_emmc())
		return 1;

	if (sector_count == 0)
		return 0;

	if ((start_sector + sector_count) > qcfw_emmc_get_sector_count())
		return 1;

	static const uint32_t sector_size = 512;
	static const uint32_t masked_sector_count = (0x40000 / sector_size);

	if (start_sector < masked_sector_count)
	{
		const uint8_t* buff = (const uint8_t*)buf;

		uint32_t leftSectorCount = sector_count;
		uint32_t fillSectorCount = (masked_sector_count - start_sector);

		if (fillSectorCount > leftSectorCount)
			fillSectorCount = leftSectorCount;

		uint32_t totalSizeToFillInBytes = (fillSectorCount * sector_size);

		leftSectorCount -= fillSectorCount;

		if (leftSectorCount > 0)
			return lv2_storage_write(dev_handle, unknown1, 0, leftSectorCount, &buff[totalSizeToFillInBytes], unknown2, flags);

		return 0;
	}

	return lv2_storage_write(dev_handle, unknown1, (start_sector - masked_sector_count), sector_count, buf, unknown2, flags);
}

bool qcfw_emmc_read(uint64_t offset, void* data, uint32_t size, uint32_t burst_size)
{
	uint8_t* dataa = (uint8_t*)data;

	if (data == NULL)
		return false;

	if (size == 0)
		return true;

	if ((offset + size) > qcfw_emmc_get_size())
		return false;

	if (!qcfw_is_emmc())
		return false;

	int32_t res;

	uint32_t unknown2;

	uint64_t dev_id = 0x100000000000001ull;
	uint64_t dev_flags = 0x22ull;

	static const uint32_t sector_size = 512;

	if ((burst_size == 0) || ((burst_size % sector_size) != 0))
		return false;

	uint32_t dev_handle;

	res = lv2_storage_open(dev_id, &dev_handle);
	if (res != 0)
		return false;

	uint8_t buf[sector_size];

	uint64_t curOffset = offset;
	uint32_t curDataOffset = 0;

	uint32_t left = size;

	while (left > 0)
	{
		uint32_t processSize = (left > sector_size) ? sector_size : left;
		uint32_t zzz = (curOffset % sector_size);
		uint32_t yyy = (sector_size - zzz);
		uint32_t xxx = (yyy > processSize) ? processSize : yyy;

		uint32_t sector_idx = (curOffset / sector_size);

		while (burst_size > left)
			burst_size -= sector_size;

		if ((zzz != 0) || (processSize != sector_size))
		{
			res = qcfw_lv2_storage_read_emmc(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			memcpy(&dataa[curDataOffset], &buf[zzz], xxx);

			curOffset += xxx;
			curDataOffset += xxx;

			left -= xxx;
		}
		else if ((burst_size > 0) && (left >= burst_size) && ((burst_size % sector_size) == 0))
		{
			res = qcfw_lv2_storage_read_emmc(dev_handle, 0, sector_idx, (burst_size / sector_size), &dataa[curDataOffset], &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			curOffset += burst_size;
			curDataOffset += burst_size;

			left -= burst_size;
		}
		else
		{
			res = qcfw_lv2_storage_read_emmc(dev_handle, 0, sector_idx, 1, &dataa[curDataOffset], &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
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

	return true;
}

bool qcfw_emmc_write(uint64_t offset, const void* data, uint32_t size, uint32_t burst_size)
{
	const uint8_t* dataa = (const uint8_t*)data;

	if (data == NULL)
		return false;

	if (size == 0)
		return true;

	if ((offset + size) > qcfw_emmc_get_size())
		return false;

	if (!qcfw_is_emmc())
		return false;

	int32_t res;

	uint32_t unknown2;

	uint64_t dev_id = 0x100000000000001ull;
	uint64_t dev_flags = 0x22ull;

	static const uint32_t sector_size = 512;

	if ((burst_size == 0) || ((burst_size % sector_size) != 0))
		return false;

	uint32_t dev_handle;

	res = lv2_storage_open(dev_id, &dev_handle);
	if (res != 0)
		return false;

	uint8_t buf[sector_size];

	uint64_t curOffset = offset;
	uint32_t curDataOffset = 0;

	uint32_t left = size;

	while (left > 0)
	{
		uint32_t processSize = (left > sector_size) ? sector_size : left;
		uint32_t zzz = (curOffset % sector_size);
		uint32_t yyy = (sector_size - zzz);
		uint32_t xxx = (yyy > processSize) ? processSize : yyy;

		uint32_t sector_idx = (curOffset / sector_size);

		while (burst_size > left)
			burst_size -= sector_size;

		if ((zzz != 0) || (processSize != sector_size))
		{
			res = qcfw_lv2_storage_read_emmc(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			memcpy(&buf[zzz], &dataa[curDataOffset], xxx);

			res = qcfw_lv2_storage_write_emmc(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			curOffset += xxx;
			curDataOffset += xxx;

			left -= xxx;
		}
		else if ((burst_size > 0) && (left >= burst_size) && ((burst_size % sector_size) == 0))
		{
			res = qcfw_lv2_storage_write_emmc(dev_handle, 0, sector_idx, (burst_size / sector_size), &dataa[curDataOffset], &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
				return false;
			}

			curOffset += burst_size;
			curDataOffset += burst_size;

			left -= burst_size;
		}
		else
		{
			res = qcfw_lv2_storage_write_emmc(dev_handle, 0, sector_idx, 1, &dataa[curDataOffset], &unknown2, dev_flags);

			if (res != 0)
			{
				lv2_storage_close(dev_handle);
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

	return true;
}

bool qcfw_dump_emmc_to_file(uint64_t offset, uint64_t size, const char* filePath, uint32_t chunk_size)
{
	if (chunk_size == 0)
		return false;

	uint8_t* chunkBuf = (uint8_t*)malloc__(chunk_size);
	if (chunkBuf == NULL)
		return false;

	int32_t fd;
	if (cellFsOpen(filePath, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != CELL_FS_SUCCEEDED)
	{
		free__(chunkBuf);
		return false;
	}

	cellFsChmod(filePath, 0777);

	{
		uint64_t left = size;
		uint64_t curEmmcOffset = offset;

		while (left > 0)
		{
			uint32_t processSize = (left > chunk_size) ? chunk_size : left;
			uint64_t writeSuccessSize = 0;

			if
				(
					!qcfw_emmc_read(curEmmcOffset, chunkBuf, processSize, chunk_size) ||
					(cellFsWrite(fd, chunkBuf, processSize, &writeSuccessSize) != CELL_FS_SUCCEEDED) ||
					(writeSuccessSize != processSize)
				)
			{
				cellFsClose(fd);
				free__(chunkBuf);

				return false;
			}

			curEmmcOffset += processSize;
			left -= processSize;
		}
	}

	cellFsClose(fd);
	free__(chunkBuf);

	return true;
}

bool qcfw_calc_crc32_from_emmc(uint64_t offset, uint64_t size, uint32_t chunk_size, uint32_t* out_crc32)
{
	if (chunk_size == 0)
		return false;

	uint8_t* chunkBuf = (uint8_t*)malloc__(chunk_size);
	if (chunkBuf == NULL)
		return false;

	uint32_t crc32 = 0;

	{
		uint64_t left = size;
		uint64_t curEmmcOffset = offset;

		while (left > 0)
		{
			uint32_t processSize = (left > chunk_size) ? chunk_size : left;

			if (!qcfw_emmc_read(curEmmcOffset, chunkBuf, processSize, (256 * 1024)))
			{
				free__(chunkBuf);
				return false;
			}

			crc32 = qcfw_crc32c(crc32, chunkBuf, processSize);

			curEmmcOffset += processSize;
			left -= processSize;
		}
	}

	if (out_crc32 != NULL)
		*out_crc32 = crc32;

	free__(chunkBuf);
	return true;
}

bool qcfw_install_stagex(bool showSuccess)
{
	bool is_nor = qcfw_is_nor();
	bool is_emmc = qcfw_is_emmc();

	if (!(is_nor || is_emmc))
	{
		PrintString(L"Flash is not supported!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (!qcfw_sc_write_request_os_bank_indicator(0xff))
		return false;

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
		(stagex_stat.st_size == 0) || (stagex_stat.st_size > (0xF000)) || // 60KiB
		(stagex_aux_stat.st_size == 0) || (stagex_aux_stat.st_size > (0x10000)) // 64KiB
	)
	{
		PrintString(L"Bad file size!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	uint32_t stagex_crc32 = 0;
	if (!qcfw_calc_crc32_from_file(stagex_path, &stagex_crc32))
	{
		PrintString(L"Stagex CRC32 calc failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	uint32_t stagex_aux_crc32 = 0;
	if (!qcfw_calc_crc32_from_file(stagex_aux_path, &stagex_aux_crc32))
	{
		PrintString(L"Stagex_aux CRC32 calc failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	uint32_t expected_stagex_crc32 = 0;
	uint32_t expected_stagex_aux_crc32 = 0;
	if (!qcfw_get_qcfw_crc32("/dev_usb000/qcfw/qcfw.crc32", &expected_stagex_crc32, &expected_stagex_aux_crc32, NULL))
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

	// modchip v1 -> v2 migrate (NOR)
	bool is_modchip_v1_to_v2_migrate = false;

	if (is_nor) // nor only
	{
		uint8_t shadow_os_bank_indicator = 0xff;
		if (!qcfw_sc_read_shadow_os_bank_indicator(&shadow_os_bank_indicator))
			return false;

		if (shadow_os_bank_indicator != 0xff) // old install only
		{
			uint8_t modchip_version = 0xff;
			if (!qcfw_sc_read_modchip_version(&modchip_version))
				return false;

			if (modchip_version == 0xff) // this is modchip v1
			{
				is_modchip_v1_to_v2_migrate = true;

				uint64_t payload[4];
				payload[0] = 0x480000057C6802A6ULL;
				payload[1] = 0x3863FFFCE8830018ULL;
				payload[2] = 0x7C8903A64E800420ULL;
				payload[3] = 0x000002401FF21000ULL; // v2

				uint64_t payload_flash[4];
				if (!qcfw_nor_read(0x31000, payload_flash, 32, 512))
					return false;

				if (memcmp(payload_flash, payload, 32) != 0)
				{
					buzzer(DOUBLE_BEEP);

					if (!qcfw_nor_write(0x31000, payload, 32, 512))
						return false;
				}
				else
					buzzer(TRIPLE_BEEP);
			}
			else
				buzzer(SINGLE_BEEP);
		}
	}

	//

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

	if (is_nor)
	{
		if (!qcfw_nor_write(0xF21000, tmpDataBuf, (uint32_t)stagex_stat.st_size, (64 * 1024))) // careful!
		{
			free__(tmpDataBuf);
			tmpDataBuf = NULL;

			PrintString(L"NorWrite failed!", XAI_PLUGIN, TEX_ERROR);
			return false;
		}
	}
	else if (is_emmc)
	{
		if (!qcfw_emmc_write(0xA1000, tmpDataBuf, (uint32_t)stagex_stat.st_size, (64 * 1024))) // careful!
		{
			free__(tmpDataBuf);
			tmpDataBuf = NULL;

			PrintString(L"EmmcWrite failed!", XAI_PLUGIN, TEX_ERROR);
			return false;
		}
	}
	else
	{
		free__(tmpDataBuf);
		tmpDataBuf = NULL;

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

	if (is_nor)
	{
		if (!qcfw_nor_write(0xF30000, tmpDataBuf, (uint32_t)stagex_aux_stat.st_size, (64 * 1024))) // careful!
		{
			free__(tmpDataBuf);
			tmpDataBuf = NULL;

			PrintString(L"NorWrite failed!", XAI_PLUGIN, TEX_ERROR);
			return false;
		}
	}
	else if (is_emmc)
	{
		if (!qcfw_emmc_write(0xB0000, tmpDataBuf, (uint32_t)stagex_aux_stat.st_size, (64 * 1024))) // careful!
		{
			free__(tmpDataBuf);
			tmpDataBuf = NULL;

			PrintString(L"EmmcWrite failed!", XAI_PLUGIN, TEX_ERROR);
			return false;
		}
	}
	else
	{
		free__(tmpDataBuf);
		tmpDataBuf = NULL;

		return false;
	}

	//

	free__(tmpDataBuf);
	tmpDataBuf = NULL;

	//

	if (!qcfw_sc_write_stagex_size((uint32_t)stagex_stat.st_size) ||
		!qcfw_sc_write_stagex_crc32(stagex_crc32) ||
		!qcfw_sc_write_stagex_aux_size((uint32_t)stagex_aux_stat.st_size) ||
		!qcfw_sc_write_stagex_aux_crc32(stagex_aux_crc32))
	{
		PrintString(L"Write Stagex/Aux size/crc32 failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (!qcfw_sc_write_stagex_size_bak((uint32_t)stagex_stat.st_size) ||
		!qcfw_sc_write_stagex_crc32_bak(stagex_crc32) ||
		!qcfw_sc_write_stagex_aux_size_bak((uint32_t)stagex_aux_stat.st_size) ||
		!qcfw_sc_write_stagex_aux_crc32_bak(stagex_aux_crc32))
	{
		PrintString(L"Write Stagex/Aux size/crc32 bak failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	//

	if (showSuccess)
	{
		if (is_nor)
		{
			if (is_modchip_v1_to_v2_migrate)
				PrintString(L"Success! (NOR v1 -> v2 migrate)\n.uf2 update recommended", XAI_PLUGIN, TEX_SUCCESS);
			else
				PrintString(L"Success! (NOR v2)", XAI_PLUGIN, TEX_SUCCESS);
		}
		else if (is_emmc)
			PrintString(L"Success! (eMMC v2)", XAI_PLUGIN, TEX_SUCCESS);
	}

	//

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

struct ros_s
{
	uint64_t offset1; // 0x20 or 0x700010
	uint64_t offset2; // 0x20 or 0x700010

	uint64_t region_size; // 0xE00000

	uint64_t unknown; // 0
};

bool qcfw_install_qcfw()
{
	bool is_nor = qcfw_is_nor();
	bool is_emmc = qcfw_is_emmc();

	if (!(is_nor || is_emmc))
	{
		PrintString(L"Flash is not supported!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

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
		PrintString(L"Reinstall HFW once then try again.", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (is_emmc)
	{
		ros_s ros;
		ros.offset1 = 0;
		ros.offset2 = 0;
		ros.region_size = 0;
		ros.unknown = 1;
		
		if (!qcfw_emmc_read(0xC0000, &ros, sizeof(ros), 512))
			return false;

		if ((ros.offset1 != 0x700010) || (ros.offset2 != 0x700010) || (ros.region_size != 0xE00000) || (ros.unknown != 0))
		{
			PrintString(L"ros header check failed!", XAI_PLUGIN, TEX_ERROR);
			return false;
		}
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
		(coreos_stat.st_size == 0) || (coreos_stat.st_size != (0x6FFFF0))
	)
	{
		PrintString(L"Bad file size!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (!qcfw_install_stagex(false))
		return false;

	uint32_t coreos_crc32 = 0;
	if (!qcfw_calc_crc32_from_file(coreos_path, &coreos_crc32))
	{
		PrintString(L"CoreOS CRC32 calc failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	uint32_t expected_coreos_crc32 = 0;
	if (!qcfw_get_qcfw_crc32("/dev_usb000/qcfw/qcfw.crc32", NULL, NULL, &expected_coreos_crc32))
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
				if (is_nor)
				{
					result = qcfw_nor_write(
						(0x0C0000 + curFileOffset), // careful!

						tmpDataBuf,
						processSize,

						tmpDataBuf_MaxSize
					);
				}
				else if (is_emmc)
				{
					result = qcfw_emmc_write(
						(0x0C0020 + curFileOffset), // careful!

						tmpDataBuf,
						processSize,

						tmpDataBuf_MaxSize
					);
				}
				else
					result = false;
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

	// calc and store ros crc32
	{
		uint32_t ros0_crc32 = 0;
		uint32_t ros1_crc32 = 0;

		if (is_nor)
		{
			if (!qcfw_calc_crc32_from_nor(0x0C0000, 0x6FFFF0, (256 * 1024), &ros0_crc32) ||
				!qcfw_calc_crc32_from_nor(0x7C0000, 0x6FFFF0, (256 * 1024), &ros1_crc32))
			{
				PrintString(L"Calc ros crc32 failed!", XAI_PLUGIN, TEX_ERROR);
				return false;
			}
		}
		else if (is_emmc)
		{
			if (!qcfw_calc_crc32_from_emmc(0x0C0020, 0x6FFFF0, (256 * 1024), &ros0_crc32) ||
				!qcfw_calc_crc32_from_emmc(0x7C0010, 0x6FFFF0, (256 * 1024), &ros1_crc32))
			{
				PrintString(L"Calc ros crc32 failed!", XAI_PLUGIN, TEX_ERROR);
				return false;
			}
		}
		else
			return false;

		if (ros0_crc32 != coreos_crc32)
		{
			PrintString(L"CoreOS crc32 check after flash failed!", XAI_PLUGIN, TEX_ERROR);
			return false;
		}

		if (!qcfw_sc_write_ros0_crc32(ros0_crc32) ||
			!qcfw_sc_write_ros1_crc32(ros1_crc32))
		{
			PrintString(L"Write ros crc32 failed!", XAI_PLUGIN, TEX_ERROR);
			return false;
		}

		if (!qcfw_sc_write_ros0_crc32_bak(ros0_crc32) ||
			!qcfw_sc_write_ros1_crc32_bak(ros1_crc32))
		{
			PrintString(L"Write ros crc32 bak failed!", XAI_PLUGIN, TEX_ERROR);
			return false;
		}
	}

	// only wipe and copy dev_blind if /dev_usb000/qcfw/dev_flash directory exists

	{
		const char* usb_dirPath = "/dev_usb000/qcfw/dev_flash";
		int32_t usb_fd;

		if (cellFsOpendir(usb_dirPath, &usb_fd) == CELL_FS_SUCCEEDED)
		{
			cellFsClosedir(usb_fd);

			bool result = false;

			for (uint32_t i = 0; i < 2; ++i)
			{
				//

				qcfw_umount("/dev_rewrite");
				umount_dev_blind();
				qcfw_umount("/dev_flash");

				qcfw_newfs_dev_flash();

				qcfw_mount_dev_flash();
				mount_dev_blind();

				//

				qcfw_rmdir("/dev_blind");

				//

				result = qcfw_cpdir(usb_dirPath, "/dev_blind");
				if (result)
					break;
			}

			if (!result)
			{
				PrintString(L"Copy dev_flash failed!", XAI_PLUGIN, TEX_ERROR);
				return false;
			}
		}
	}

	qcfw_fs_sync("/dev_blind");
	qcfw_fs_sync("/dev_flash");

	if (!qcfw_sc_write_request_os_bank_indicator(0x1))
	{
		PrintString(L"Bank switch failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	sys_timer_sleep(5);
	
	rebootXMB(SYS_SOFT_REBOOT);
	return true;
}

bool qcfw_dump_nor_to_usb()
{
	if (!qcfw_is_nor())
	{
		PrintString(L"Flash is not NOR!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (!qcfw_dump_nor_to_file(0, (16 * 1024 * 1024), "/dev_usb000/NOR.bin", (256 * 1024)))
	{
		PrintString(L"Failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	PrintString(L"Success!", XAI_PLUGIN, TEX_SUCCESS);
	return true;
}

bool qcfw_emmc_is_complete()
{
	if (!qcfw_is_emmc())
		return false;

	uint8_t lv0ldr_region_dump_status = 0xff;
	if (!qcfw_sc_read_lv0ldr_region_dump_status(&lv0ldr_region_dump_status))
		return false;

	if (lv0ldr_region_dump_status != 0x27)
		return false;

	uint32_t lv0ldr_region_crc32 = 0;
	if (!qcfw_sc_read_lv0ldr_region_crc32(&lv0ldr_region_crc32))
		return false;

	static const uint32_t dumpSize = 0x40000;

	static const uint32_t tmpDataBuf_MaxSize = dumpSize;
	uint8_t* tmpDataBuf = (uint8_t*)malloc__(tmpDataBuf_MaxSize);

	if (tmpDataBuf == NULL)
		return false;

	if (!qcfw_emmc_read(0xF000000, tmpDataBuf, dumpSize, (256 * 1024)))
	{
		free__(tmpDataBuf);
		return false;
	}

	uint32_t lv0ldr_bottom_region_crc32 = qcfw_crc32c(0, tmpDataBuf, dumpSize);
	if (lv0ldr_bottom_region_crc32 != lv0ldr_region_crc32)
	{
		free__(tmpDataBuf);
		return false;
	}

	free__(tmpDataBuf);
	return true;
}

bool qcfw_dump_emmc_to_usb_256M()
{
	if (!qcfw_is_emmc())
	{
		PrintString(L"Flash is not eMMC!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	bool is_complete = qcfw_emmc_is_complete();

	if (!qcfw_dump_emmc_to_file(0, (256 * 1024 * 1024), (is_complete ? "/dev_usb000/eMMC_complete_256M.bin" : "/dev_usb000/eMMC_incomplete_256M.bin"), (256 * 1024)))
	{
		PrintString(L"Failed!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	if (is_complete)
		PrintString(L"Success! (complete)", XAI_PLUGIN, TEX_SUCCESS);
	else
		PrintString(L"Success! (incomplete)", XAI_PLUGIN, TEX_SUCCESS);

	return true;
}

bool qcfw_dump_emmc_to_usb_12G()
{
	if (!qcfw_is_emmc())
	{
		PrintString(L"Flash is not eMMC!", XAI_PLUGIN, TEX_ERROR);
		return false;
	}

	bool is_complete = qcfw_emmc_is_complete();

	const uint64_t dump_size = qcfw_emmc_get_size();
	static const uint64_t chunk_size = (3ULL * 1024ULL * 1024ULL * 1024ULL);

	uint64_t cur_offset = 0;
	uint64_t left = dump_size;

	uint32_t i = 0;

	while (left > 0)
	{
		uint64_t processSize = (left > chunk_size) ? chunk_size : left;

		char path[512];

		if (is_complete)
			sprintf_(path, "/dev_usb000/eMMC_complete_12G_%u.bin", i);
		else
			sprintf_(path, "/dev_usb000/eMMC_incomplete_12G_%u.bin", i);

		if (!qcfw_dump_emmc_to_file(cur_offset, processSize, path, (256 * 1024)))
		{
			PrintString(L"Failed!", XAI_PLUGIN, TEX_ERROR);
			return false;
		}

		cur_offset += processSize;
		left -= processSize;

		++i;
	}

	if (is_complete)
		PrintString(L"Success! (complete)", XAI_PLUGIN, TEX_SUCCESS);
	else
		PrintString(L"Success! (incomplete)", XAI_PLUGIN, TEX_SUCCESS);

	return true;
}