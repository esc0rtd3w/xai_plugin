#include <string.h>
//#include <stdlib.h>
//#include <math.h>
#include <cell/fs/cell_fs_file_api.h>
//#include <sys/fs_external.h>
#include <sys/timer.h>
#include "badwdsd.h"
#include "functions.h"
#include "gccpch.h"
#include "log.h"
#include "hfw_settings.h"
#include "lv1.h"
#include "hen.h"

/*bool IsFileExist(const char* path)
{
	FILE* f = fopen(path, "rb");

	if (f == NULL)
		return false;

	fclose(f);
	return true;
}*/

bool IsFileExist(const char* path)
{
    CellFsStat stat;
    int rc = cellFsStat(path, &stat);
    return (rc == CELL_OK);
}

/*size_t GetFileSize(FILE* f)
{
	size_t old = ftell(f);

	fseek(f, 0, SEEK_END);
	size_t size = ftell(f);

	fseek(f, old, SEEK_SET);
	return size;
}*/

size_t GetFileSize(const char* path)
{
    CellFsStat stat;
    int rc = cellFsStat(path, &stat);
    if (rc != CELL_OK)
        return 0;
    return stat.st_size;
}

// UM EEPROM
void patch_um(void)
{
	showMessageRaw("Patching Update Manager EEPROM Read\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    uint64_t pud_er = 0x6000000038000001ULL;
    lv1_write(0xFC4DC, 8, &pud_er);

	showMessageRaw("Patching Update Manager EEPROM Write\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    uint64_t pud_ew = 0x6000000038000001ULL;
    lv1_write(0xFEA38, 8, &pud_ew);

	showMessageRaw("Patching Dispatch Manager\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	uint32_t pdm1 = 0x60000000;
	lv1_write(0x16FA64, 4, &pdm1);

	uint32_t pdm2 = 0x38600001;
	lv1_write(0x16FA88, 4, &pdm2);

	uint8_t pdm3[12] = {0x3b, 0xe0, 0x00, 0x01, 0x9b, 0xe1, 0x00, 0x70, 0x38, 0x60, 0x00, 0x00};
	lv1_write(0x16FB00, 12, pdm3);

	showMessageRaw("Patching service auth\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	uint64_t psa = 0x2f80000048000050ULL;
	lv1_write(0x16FB64, 8, &psa);
}

void patch_um_eeprom(void)
{
	showMessageRaw("Patching Update Manager EEPROM Read\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    uint64_t pud_er = 0x6000000038000001ULL;
    lv1_write(0xFC4DC, 8, &pud_er);

	showMessageRaw("Patching Update Manager EEPROM Write\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    uint64_t pud_ew = 0x6000000038000001ULL;
    lv1_write(0xFEA38, 8, &pud_ew);
}

/*double GetFWVersion(void)
{
	FILE *fp;
	fp = fopen("/dev_flash/vsh/etc/version.txt", "rb");

	if (fp != NULL)
	{
		char bufs[1024];
		double fwversion = 0.0;
		fgets(bufs, 1024, fp);
		fclose(fp);

		fwversion = strtod(bufs + 8, NULL);
	}
}*/

double GetFWVersion(void)
{
    char bufs[64];
    double version = 0.0;

    CellFsStat stat;
    int32_t rc = cellFsStat("/dev_flash/vsh/etc/version.txt", &stat);
    showMessageRaw(msgf("cellFsStat() rc = 0x%08X, size = %llu", (uint32_t)rc, stat.st_size), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
    if (rc != CELL_OK)
    {
        showMessageRaw("Failed to stat version.txt", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
        return 0.0;
    }

    int32_t fd;
    rc = cellFsOpen("/dev_flash/vsh/etc/version.txt", CELL_FS_O_RDONLY, &fd, NULL, 0);
    showMessageRaw(msgf("cellFsOpen() rc = 0x%08X", (uint32_t)rc), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
    if (rc != CELL_OK)
    {
        showMessageRaw("Failed to open version.txt", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
        return 0.0;
    }

    uint64_t to_read = stat.st_size < (sizeof(bufs) - 1) ? stat.st_size : (sizeof(bufs) - 1);
    uint64_t len = 0;
    rc = cellFsRead(fd, bufs, to_read, &len);
    cellFsClose(fd);
    showMessageRaw(msgf("cellFsRead() rc = 0x%08X, bytes = %llu", (uint32_t)rc, len), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
    if (rc != CELL_OK || len < 14)  // need at least "release:0X.XX00:"
    {
        showMessageRaw("Failed to read release string from version.txt", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
        return 0.0;
    }

    bufs[len] = '\0';
    showMessageRaw(msgf("Raw file contents: %s", bufs), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

    char* p = bufs + 8;  // skip "release:"
    showMessageRaw(msgf("Parsing at '%c%c.%c%c'", p[0], p[1], p[3], p[4]), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

    int ip = (p[0] - '0') * 10 + (p[1] - '0');
    int fp = (p[3] - '0') * 10 + (p[4] - '0');
    version = (double)ip + ((double)fp / 100.0);

    if (version == 0.0)
    {
        showMessageRaw("Failed to get firmware version", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
    }
    else
    {
        char msg[64];
        vsh_sprintf(msg, "Firmware Version: %.2f", version);
        showMessageRaw(msg, (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
    }

    return version;
}

bool CheckFWVersion()
{
	if (GetFWVersion() < 4.70)
	{
		showMessageRaw("Firmware NOT supported!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return false;
	}
	else
	{
		showMessageRaw("Firmware supported!\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
		return true;
	}
}

void lv1_read(uint64_t addr, uint64_t size, void *out_Buf)
{
	if (size == 0)
		return;

	uint64_t curOffset = 0;
	uint64_t left = size;

	uint64_t chunkSize = sizeof(uint64_t);

	uint8_t *outBuf = (uint8_t *)out_Buf;

	uint64_t zz = (addr % chunkSize);

	if (zz != 0)
	{
		uint64_t readSize = (chunkSize - zz);

		if (readSize > left)
			readSize = left;

		uint64_t a = (addr - zz);

		uint64_t v = lv1_peek(a);
		uint8_t *vx = (uint8_t *)&v;

		memcpy(&outBuf[curOffset], &vx[zz], readSize);

		curOffset += readSize;
		left -= readSize;
	}

	while (1)
	{
		if (left == 0)
			break;

		uint64_t readSize = (left > chunkSize) ? chunkSize : left;

		uint64_t v = lv1_peek(addr + curOffset);

		memcpy(&outBuf[curOffset], &v, readSize);

		curOffset += readSize;
		left -= readSize;
	}
}

void lv1_write(uint64_t addr, uint64_t size, const void *in_Buf)
{
	if (size == 0)
		return;

	uint64_t curOffset = 0;
	uint64_t left = size;

	uint64_t chunkSize = sizeof(uint64_t);

	const uint8_t *inBuf = (const uint8_t *)in_Buf;

	uint64_t zz = (addr % chunkSize);

	if (zz != 0)
	{
		uint64_t writeSize = (chunkSize - zz);

		if (writeSize > left)
			writeSize = left;

		uint64_t a = (addr - zz);

		uint64_t v = lv1_peek(a);
		uint8_t *vx = (uint8_t *)&v;

		memcpy(&vx[zz], &inBuf[curOffset], writeSize);

		lv1_poke(a, v);

		curOffset += writeSize;
		left -= writeSize;
	}

	while (1)
	{
		if (left == 0)
			break;

		uint64_t writeSize = (left > chunkSize) ? chunkSize : left;

		uint64_t v = lv1_peek(addr + curOffset);
		memcpy(&v, &inBuf[curOffset], writeSize);

		lv1_poke(addr + curOffset, v);

		curOffset += writeSize;
		left -= writeSize;
	}
}

bool IsExploited()
{
	//uint64_t lpar_addr;
	
	//int32_t res;
	//res = lv1_map_physical_address_region(0, EXP_4KB, SIZE_4KB, &lpar_addr);

	uint64_t addr = 0x323740;// 0000000000323740  53 6F 6E 79 20 43 65 6C  Sony Cel
	uint64_t verify = lv1_peek(addr);

	if (verify != 0x536F6E792043656CULL)
	{
		showMessageRaw("IsExploited: false", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return false;
	}

	/*res = lv1_unmap_physical_address_region(lpar_addr);

	if (res != 0)
	{
		showMessageRaw(msgf("lv1_unmap_physical_address_region failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return false;
	}*/

	showMessageRaw("IsExploited: true", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return true;
}

uint8_t get_bank_indicator()
{
	uint8_t value = 0x99;

	int32_t res = update_mgr_read_eeprom(0x48c24, &value);

	if (res != 0)
	{
		showMessageRaw(msgf("update_mgr_read_eeprom failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 0x99;
	}

	return value;
}

void set_bank_indicator(uint8_t value)
{
	int32_t res = update_mgr_write_eeprom(0x48c24, value);

	if (res != 0)
	{
		showMessageRaw(msgf("update_mgr_write_eeprom failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}
}

bool FlashIsNor()
{
	uint8_t flag;

	int32_t res = lv2_ss_get_cache_of_flash_ext_flag(&flag);

	if (res != 0)
	{
		showMessageRaw(msgf("lv2_storage_get_cache_of_flash_ext_flag failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return false;
	}

	// bit 0 set means NAND; cleared means NOR
	showMessageRaw(msgf("lv2_storage_get_cache_of_flash_ext_flag, res = %d, flag = 0x%02x\n", res, (uint32_t)flag), (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return !(flag & 0x1);
}

bool TargetIsCEX()
{
	uint64_t type;

	int32_t res = lv2_dbg_get_console_type(&type);

	if (res != 0)
	{
		showMessageRaw(msgf("lv2_dbg_get_console_type failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return false;
	}

	//showMessageRaw(msgf("lv2_dbg_get_console_type = 1, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return (type == 1);
}

bool TargetIsDEX()
{
	uint64_t type;

	int32_t res = lv2_dbg_get_console_type(&type);

	if (res != 0)
	{
		showMessageRaw(msgf("lv2_dbg_get_console_type failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return false;
	}
	
	//showMessageRaw(msgf("lv2_dbg_get_console_type = 2, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return (type == 2);
}

bool TargetIsDECR()
{
	uint64_t type;

	int32_t res = lv2_dbg_get_console_type(&type);

	if (res != 0)
	{
		showMessageRaw(msgf("lv2_dbg_get_console_type failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return false;
	}
	
	//showMessageRaw(msgf("lv2_dbg_get_console_type = 3, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return (type == 3);
}

void NorWrite(uint64_t offset, const void* data, uint64_t size)
{
	const uint8_t* dataa = (const uint8_t*)data;

	showMessageRaw(msgf("NorWrite() offset = 0x%lx, data = 0x%lx, size = %lu\n", offset, (uint64_t)data, size), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	if (data == NULL)
		return;

	if (size == 0)
		return;

	if (!FlashIsNor())
	{
		showMessageRaw("Flash is not nor!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	int32_t res;

	uint32_t unknown2;

	uint64_t dev_id = 0x100000000000004ull;
	uint64_t dev_flags = 0x22ull;

	static const uint64_t sector_size = 512;
	uint64_t burst_size = (512 * sector_size);

	showMessageRaw(msgf("burst_size = %lu\n", burst_size), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	uint32_t dev_handle;

	res = lv2_storage_open(dev_id, &dev_handle);

	if (res != 0)
	{
		showMessageRaw(msgf("lv2_storage_open failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	char* buf = (char*)malloc_(burst_size);

	if (buf == NULL)
	{
		showMessageRaw("malloc failed!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	uint64_t curOffset = offset;
	uint64_t curDataOffset = 0;

	uint64_t left = size;

	while (left > 0)
	{
		uint64_t processSize = (left > sector_size) ? sector_size : left;
		uint64_t zzz = (curOffset % sector_size);
		uint64_t yyy = (sector_size - zzz);
		uint64_t xxx = (yyy > processSize) ? processSize : yyy;

		uint64_t sector_idx = (curOffset / sector_size);

		showMessageRaw(msgf("curOffset = 0x%lx, curDataOffset = 0x%lx, processSize = %lu, zzz = %lu, yyy = %lu, xxx = %lu, sector_idx = %lu, left = %lu\n",
			curOffset, curDataOffset, processSize, zzz, yyy, xxx, sector_idx, left), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

		if (burst_size > left)
		{
			while (burst_size > left)
				burst_size -= sector_size;

			showMessageRaw(msgf("burst_size = %lu\n", burst_size), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		}

		if ((zzz != 0) || (processSize != sector_size))
		{
			showMessageRaw("1\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessageRaw(msgf("lv2_storage_read failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}

			memcpy(&buf[zzz], &dataa[curDataOffset], xxx);

			res = lv2_storage_write(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessageRaw(msgf("lv2_storage_write failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}

			curOffset += xxx;
			curDataOffset += xxx;

			left -= xxx;
		}
		else if ((burst_size > 0) && (left >= burst_size) && ((burst_size % sector_size) == 0))
		{
			showMessageRaw("2\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

			memcpy(&buf[0], &dataa[curDataOffset], burst_size);

			res = lv2_storage_write(dev_handle, 0, sector_idx, (burst_size / sector_size), buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessageRaw(msgf("lv2_storage_write failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}

			curOffset += burst_size;
			curDataOffset += burst_size;

			left -= burst_size;
		}
		else
		{
			showMessageRaw("3\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

			memcpy(&buf[0], &dataa[curDataOffset], processSize);

			res = lv2_storage_write(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessageRaw(msgf("lv2_storage_write failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}

			curOffset += processSize;
			curDataOffset += processSize;

			left -= processSize;
		}
	}

	res = lv2_storage_close(dev_handle);

	if (res != 0)
	{
		showMessageRaw(msgf("lv2_storage_close failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	free_(buf);

	showMessageRaw("NorWrite() done.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

void NorRead(uint64_t offset, void* data, uint64_t size)
{
	uint8_t* dataa = (uint8_t*)data;

	showMessageRaw(msgf("NorRead() offset = 0x%lx, data = 0x%lx, size = %lu\n", offset, (uint64_t)data, size), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	if (data == NULL)
		return;

	if (size == 0)
		return;

	if (!FlashIsNor())
	{
		showMessageRaw("Flash is not nor!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	int32_t res;

	uint32_t unknown2;

	uint64_t dev_id = 0x100000000000004ull;
	uint64_t dev_flags = 0x22ull;

	static const uint64_t sector_size = 512;
	uint64_t burst_size = (512 * sector_size);

	showMessageRaw(msgf("burst_size = %lu\n", burst_size), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	uint32_t dev_handle;

	res = lv2_storage_open(dev_id, &dev_handle);

	if (res != 0)
	{
		showMessageRaw(msgf("lv2_storage_open failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	char* buf = (char*)malloc_(burst_size);

	if (buf == NULL)
	{
		showMessageRaw("malloc failed!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	uint64_t curOffset = offset;
	uint64_t curDataOffset = 0;

	uint64_t left = size;

	while (left > 0)
	{
		uint64_t processSize = (left > sector_size) ? sector_size : left;
		uint64_t zzz = (curOffset % sector_size);
		uint64_t yyy = (sector_size - zzz);
		uint64_t xxx = (yyy > processSize) ? processSize : yyy;

		uint64_t sector_idx = (curOffset / sector_size);

		showMessageRaw(msgf("curOffset = 0x%lx, curDataOffset = 0x%lx, processSize = %lu, zzz = %lu, yyy = %lu, xxx = %lu, sector_idx = %lu, left = %lu\n",
			curOffset, curDataOffset, processSize, zzz, yyy, xxx, sector_idx, left), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

		if (burst_size > left)
		{
			while (burst_size > left)
				burst_size -= sector_size;

			showMessageRaw(msgf("burst_size = %lu\n", burst_size), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		}

		if ((zzz != 0) || (processSize != sector_size))
		{
			showMessageRaw("1\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessageRaw(msgf("lv2_storage_read failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}

			memcpy(&dataa[curDataOffset], &buf[zzz], xxx);

			curOffset += xxx;
			curDataOffset += xxx;

			left -= xxx;
		}
		else if ((burst_size > 0) && (left >= burst_size) && ((burst_size % sector_size) == 0))
		{
			showMessageRaw("2\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

			res = lv2_storage_read(dev_handle, 0, sector_idx, (burst_size / sector_size), buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessageRaw(msgf("lv2_storage_read failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}

			memcpy(&dataa[curDataOffset], &buf[0], burst_size);

			curOffset += burst_size;
			curDataOffset += burst_size;

			left -= burst_size;
		}
		else
		{
			showMessageRaw("3\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessageRaw(msgf("lv2_storage_read failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
				return;
			}

			memcpy(&dataa[curDataOffset], &buf[0], processSize);

			curOffset += processSize;
			curDataOffset += processSize;

			left -= processSize;
		}
	}

	res = lv2_storage_close(dev_handle);

	if (res != 0)
	{
		showMessageRaw(msgf("lv2_storage_close failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return;
	}

	free_(buf);

	showMessageRaw("NorRead() done.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

/*void BadWDSD_Write_Stagex()
{
	notify("BadWDSD_Write_Stagex()\n");

	if (!FlashIsNor())
	{
		notify("Flash is not nor!!!\n");
		return;
	}

	FILE *f = NULL;

	if (f == NULL)
	{
		notify("Loading /app_home/Stagex.bin\n");

		f = fopen("/app_home/Stagex.bin", "rb");

		if (f == NULL)
			notify("Not found\n");
	}

	if (f == NULL)
	{
		notify("Loading /dev_hdd0/Stagex.bin\n");

		f = fopen("/dev_hdd0/Stagex.bin", "rb");

		if (f == NULL)
			notify("Not found\n");
	}

	if (f == NULL)
	{
		notify("Stagex.bin not found!\n");
		return;
	}

	size_t size = GetFileSize(f);
	notify("size = %lu\n", size);

	void *code = malloc(size);
	fread(code, 1, size, f);

	fclose(f);

	notify("code = 0x%lx\n", (uint64_t)code);

	if (size > (48 * 1024))
	{
		notify("size is too big!!!\n");
		return;
	}

	notify("Writing to flash...\n");
	// lv1_write(0x2401F031000, size, code);
	NorWrite(0x31000, code, size);

	{
		notify("0x%lx\n", lv1_peek(0x2401F0002000ULL));
		notify("0x%lx\n", lv1_peek(0x2401F0310000ULL));
	}

	free(code);
	notify("BadWDSD_Write_Stagex() done,\n");
}*/

/*void BadWDSD_Write_ros(bool compare, bool doFlashRos1)
{
	notify("BadWDSD_Write_ros()\n");

	if (!FlashIsNor())
	{
		notify("Flash is not nor!!!\n");
		return;
	}

	FILE *f = NULL;

	if (f == NULL)
	{
		notify("Loading /app_home/CoreOS.bin\n");

		f = fopen("/app_home/CoreOS.bin", "rb");

		if (f == NULL)
			notify("Not found\n");
	}

	if (f == NULL)
	{
		notify("Loading /dev_hdd0/CoreOS.bin\n");

		f = fopen("/dev_hdd0/CoreOS.bin", "rb");

		if (f == NULL)
			notify("Not found\n");
	}

	if (f == NULL)
	{
		notify("CoreOS.bin not found!\n");
		return;
	}

	size_t size = GetFileSize(f);
	notify("size = %lu\n", size);

	void *code = malloc(size);
	fread(code, 1, size, f);

	fclose(f);

	notify("code = 0x%lx\n", (uint64_t)code);

	if (size > 0x700000)
	{
		notify("size is too big!!!\n");
		return;
	}

	if (compare)
	{
		notify("Comparing ros...\n");

		void *ros0 = malloc(0x700000);
		void *ros1 = malloc(0x700000);

		if (ros0 == NULL || ros1 == NULL)
		{
			notify("malloc fail!\n");
			return;
		}

		NorRead(0x0C0000, ros0, 0x700000);
		NorRead(0x7C0000, ros1, 0x700000);

		if (memcmp(ros0, ros1, 0x700000))
		{
			notify("ros compare fail!, please reinstall same firmware twice!\n");
			return;
		}

		free(ros1);
		free(ros0);
	}

	//notify("Writing to flash (%s)...\n", doFlashRos1 ? "ros1" : "ros0");
	NorWrite(doFlashRos1 ? 0x7C0000 : 0x0C0000, code, size);

	{
		notify("0x%lx\n", lv1_peek(0x2401F0002000ULL));
		notify("0x%lx\n", lv1_peek(0x2401F0310000ULL));
	}

	free_(code);
	notify("BadWDSD_Write_ros() done.\n");
}*/

void BadWDSD_Write_Stagex()
{
    showMessageRaw("BadWDSD_Write_Stagex()\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

    if (!FlashIsNor())
    {
        showMessageRaw("Flash is not nor!!!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return;
    }

    int fd = -1;
    int rc;

    if (fd < 0)
    {
        showMessageRaw("Loading /app_home/Stagex.bin\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        rc = cellFsOpen("/app_home/Stagex.bin", CELL_FS_O_RDONLY, &fd, NULL, 0);

        if (rc != CELL_OK)
            showMessageRaw("Not found\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
    }

    if (fd < 0)
    {
        showMessageRaw("Loading /dev_hdd0/Stagex.bin\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        rc = cellFsOpen("/dev_hdd0/Stagex.bin", CELL_FS_O_RDONLY, &fd, NULL, 0);

        if (rc != CELL_OK)
            showMessageRaw("Not found\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
    }

    if (fd < 0)
    {
        showMessageRaw("Stagex.bin not found!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return;
    }

    CellFsStat stat;
    rc = cellFsFstat(fd, &stat);
    size_t size = (rc == CELL_OK) ? stat.st_size : 0;
    showMessageRaw(msgf("size = %lu\n", size), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

    void* code = malloc_(size);
    uint64_t bytesRead;
    cellFsRead(fd, code, size, &bytesRead);

    cellFsClose(fd);

    showMessageRaw(msgf("code = 0x%lx\n", (uint64_t)code), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

    if (size > (48 * 1024))
    {
        showMessageRaw("size is too big!!!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return;
    }

    showMessageRaw("Writing to flash...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    // lv1_write(0x2401F031000, size, code);
    NorWrite(0x31000, code, size);

    {
        showMessageRaw(msgf("0x%lx\n", lv1_peek(0x2401F0002000ULL)), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
        showMessageRaw(msgf("0x%lx\n", lv1_peek(0x2401F0310000ULL)), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    }

    free_(code);
    showMessageRaw("BadWDSD_Write_Stagex() done,\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

void BadWDSD_Write_ros(bool compare, bool doFlashRos1)
{
    showMessageRaw("BadWDSD_Write_ros()\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

    if (!FlashIsNor())
    {
        showMessageRaw("Flash is not nor!!!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return;
    }

    int fd = -1;
    int rc;

    if (fd < 0)
    {
        showMessageRaw("Loading /app_home/CoreOS.bin\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        rc = cellFsOpen("/app_home/CoreOS.bin", CELL_FS_O_RDONLY, &fd, NULL, 0);

        if (rc != CELL_OK)
            showMessageRaw("Not found\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
    }

    if (fd < 0)
    {
        showMessageRaw("Loading /dev_hdd0/CoreOS.bin\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        rc = cellFsOpen("/dev_hdd0/CoreOS.bin", CELL_FS_O_RDONLY, &fd, NULL, 0);

        if (rc != CELL_OK)
            showMessageRaw("Not found\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
    }

    if (fd < 0)
    {
        showMessageRaw("CoreOS.bin not found!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return;
    }

    CellFsStat stat;
    rc = cellFsFstat(fd, &stat);
    size_t size = (rc == CELL_OK) ? stat.st_size : 0;
    showMessageRaw(msgf("size = %lu\n", size), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

    void* code = malloc_(size);
    uint64_t bytesRead;
    cellFsRead(fd, code, size, &bytesRead);

    cellFsClose(fd);

    showMessageRaw(msgf("code = 0x%lx\n", (uint64_t)code), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

    if (size > 0x700000)
    {
        showMessageRaw("size is too big!!!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return;
    }

    if (compare)
    {
        showMessageRaw("Comparing ros...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        void* ros0 = malloc_(0x700000);
        void* ros1 = malloc_(0x700000);

        if (ros0 == NULL || ros1 == NULL)
        {
            showMessageRaw("malloc fail!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
            return;
        }

        NorRead(0x0C0000, ros0, 0x700000);
        NorRead(0x7C0000, ros1, 0x700000);

        if (memcmp(ros0, ros1, 0x700000))
        {
            showMessageRaw("ros compare fail!, please reinstall same firmware twice!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
            return;
        }

        free_(ros1);
        free_(ros0);
    }
	
    //showMessageRaw(msgf("Writing to flash (%s)...\n", doFlashRos1 ? "ros1" : "ros0"), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	const char* banksel = doFlashRos1 ? "ros1" : "ros0";
    showMessageRaw(msgf("Writing to flash (%s)...\n", (char*)banksel), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    NorWrite(doFlashRos1 ? 0x7C0000 : 0x0C0000, code, size);

    {
        showMessageRaw(msgf("0x%lx\n", lv1_peek(0x2401F0002000ULL)), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
        showMessageRaw(msgf("0x%lx\n", lv1_peek(0x2401F0310000ULL)), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    }

    free_(code);
    showMessageRaw("BadWDSD_Write_ros() done.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

// BadWDSD/qCFW Installer
// returns 1 on success, 0 on failure
int InstallQCFW(bool doLegacy, bool doSkipRosCompare, bool doFlashRos1)
{
	if (GetFWVersion() < 4.70)
	{
		showMessageRaw("firmware not supported!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 0;
	}

	if (CheckFWVersion())
	{
		showMessageRaw("You have a compatible firmware version!\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
	{
		showMessageRaw("You DO NOT have a compatible firmware version!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 0;
	}

	sys_timer_sleep(3);// DEBUG sleep

	//showMessageRaw(msgf("Flash is %s\n", FlashIsNor() ? "NOR" : "NAND"), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	//const char* flashtype = (FlashIsNor() ? "NOR" : "NAND");
    //showMessageRaw(msgf(flashtype), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

	if (GetFlashType() == "NOR")
	{
		showMessageRaw("You have a compatible flash type!\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
	{
		showMessageRaw("You DO NOT have a compatible flash type!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 0;
	}

	sys_timer_sleep(3);

	/*if (TargetIsCEX())
	{
		showMessageRaw("Target is CEX\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	}
	else if (TargetIsDEX())
	{
		showMessageRaw("Target is DEX\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	}
	else if (TargetIsDECR())
	{
		showMessageRaw("Target is DECR\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	}
	else
	{
		showMessageRaw("Unknown target!!!\n", (char *)XAI_PLUGIN, (char *)TEX_WARNING);
		return 0;
	}*/

	// Return 0 if unknown
	if (GetTarget() == 0)
	{
		return 0;
	}

	showMessageRaw("DEBUG: Writing Stagex will begin in 10 seconds\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	sys_timer_sleep(10);// DEBUG sleep

    if (!doLegacy)
    {
        showMessageRaw("Installing Stagex.bin...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
        //BadWDSD_Write_Stagex();
		showMessageRaw("DEBUG: BadWDSD_Write_Stagex() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
        showMessageRaw("Stagex.bin installed.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        showMessageRaw("Installing CoreOS.bin...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        if (!IsExploited())
        {
            showMessageRaw("You MUST be exploited at this point!\nInstall modchip first!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
            // abort();
            return 0;
        }

        uint8_t bank_indicator = get_bank_indicator();
        showMessageRaw(msgf("bank_indicator = 0x%x\n", (uint32_t)bank_indicator), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        if (bank_indicator != 0x00)
        {
            showMessageRaw("Please reinstall firmware ONCE again then try again.\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
            return 0;
        }
		
		showMessageRaw("DEBUG: Writing CoreOS will begin in 10 seconds\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		sys_timer_sleep(10);// DEBUG sleep

        //BadWDSD_Write_ros(false, false);
		showMessageRaw("DEBUG: BadWDSD_Write_ros() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        set_bank_indicator(0xff);
        bank_indicator = get_bank_indicator();
        showMessageRaw(msgf("bank_indicator = 0x%x\n", (uint32_t)bank_indicator), (char *)XAI_PLUGIN, (char *)TEX_INFO2);

        if (bank_indicator != 0xff)
        {
            showMessageRaw("Bank switch failed!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
            return 0;
        }

        showMessageRaw("CoreOS.bin installed.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    }
    else
    {
        // legacy install
        showMessageRaw("Legacy install\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
        //BadWDSD_Write_Stagex();
        //BadWDSD_Write_ros(!doSkipRosCompare, doFlashRos1);
		showMessageRaw("DEBUG: BadWDSD_Write_Stagex() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
		showMessageRaw("DEBUG: BadWDSD_Write_ros() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    }

	showMessageRaw("DEBUG: return 1\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	
    sys_timer_sleep(5);
	VerifyQCFW();

    return 1;
}

// writes only the Stagex.bin payload
// returns 1 on success, 0 on failure
int InstallStagexOnly()
{
	if (CheckFWVersion())
	{
		showMessageRaw("You have a compatible firmware version!\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
	{
		showMessageRaw("You DO NOT have a compatible firmware version!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 0;
	}

	sys_timer_sleep(3);// DEBUG sleep

	if (GetFlashType() == "NOR")
	{
		showMessageRaw("You have a compatible flash type!\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
	{
		showMessageRaw("You DO NOT have a compatible flash type!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 0;
	}

	sys_timer_sleep(3);// DEBUG sleep
	
	if (GetTarget() == 0)
	{
		return 0;
	}

	sys_timer_sleep(3);// DEBUG sleep

    showMessageRaw("DEBUG: Writing Stagex will begin in 10 seconds\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    sys_timer_sleep(10);

    showMessageRaw("Installing Stagex.bin...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    //BadWDSD_Write_Stagex();
	showMessageRaw("DEBUG: BadWDSD_Write_Stagex() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    showMessageRaw("Stagex.bin installed.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

    sys_timer_sleep(5);
	VerifyStagexOnly();

    return 1;
}

// writes only the CoreOS.bin payload
// doSkipRosCompare  if true, skips the ROS‐region compare step
// doFlashRos1       if true, writes into bank1 (ros1) instead of bank0
// returns 1 on success, 0 on failure
int InstallCoreOSOnly(bool doSkipRosCompare, bool doFlashRos1)
{
	if (CheckFWVersion())
	{
		showMessageRaw("You have a compatible firmware version!\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
	{
		showMessageRaw("You DO NOT have a compatible firmware version!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 0;
	}

	sys_timer_sleep(3);// DEBUG sleep

	if (GetFlashType() == "NOR")
	{
		showMessageRaw("You have a compatible flash type!\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
	{
		showMessageRaw("You DO NOT have a compatible flash type!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return 0;
	}

	sys_timer_sleep(3);// DEBUG sleep
	
	if (GetTarget() == 0)
	{
		return 0;
	}

	sys_timer_sleep(3);// DEBUG sleep

    showMessageRaw("Installing CoreOS.bin...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    if (!IsExploited())
    {
        showMessageRaw("You MUST be exploited at this point!\nInstall modchip first!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return 0;
    }

    uint8_t bank_indicator = get_bank_indicator();
    showMessageRaw(msgf("bank_indicator = 0x%x\n", (uint32_t)bank_indicator), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    if (bank_indicator != 0x00)
    {
        showMessageRaw("Please reinstall firmware ONCE again then try again.\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return 0;
    }

    showMessageRaw("DEBUG: Writing CoreOS will begin in 10 seconds\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    sys_timer_sleep(10);

    //BadWDSD_Write_ros(!doSkipRosCompare, doFlashRos1);
	showMessageRaw("DEBUG: BadWDSD_Write_ros() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

    set_bank_indicator(0xff);
    bank_indicator = get_bank_indicator();
    showMessageRaw(msgf("bank_indicator = 0x%x\n", (uint32_t)bank_indicator), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    if (bank_indicator != 0xff)
    {
        showMessageRaw("Bank switch failed!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return 0;
    }

    showMessageRaw("CoreOS.bin installed.\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	
    sys_timer_sleep(5);
	VerifyCoreOSOnly();

    return 1;
}

void VerifyQCFW(void)
{
	showMessageRaw("VerifyQCFW: Not Yet Implemented", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

void VerifyStagexOnly(void)
{
	showMessageRaw("VerifyStagexOnly: Not Yet Implemented", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

void VerifyCoreOSOnly(void)
{
	showMessageRaw("VerifyCoreOSOnly: Not Yet Implemented", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

uint8_t GetTarget()
{
	uint8_t target = 0;

	if (TargetIsCEX())
	{
		target = 1;
		showMessageRaw("Target is CEX\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if (TargetIsDEX())
	{
		target = 2;
		showMessageRaw("Target is DEX\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if (TargetIsDECR())
	{
		target = 3;
		showMessageRaw("Target is DECR\n", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else
	{
		target = 0;
		showMessageRaw("Unknown target!!!\n", (char *)XAI_PLUGIN, (char *)TEX_WARNING);
	}
	return target;
}

const char* GetFlashType()
{
	const char* flashtype = (FlashIsNor() ? "NOR" : "NAND");
	showMessage(msgf(flashtype), (char *)XAI_PLUGIN, (char *)TEX_INFO2);
	return flashtype;
}

void CompareROSBanks(void)
{
    showMessageRaw("Comparing ros...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO2);

    void* ros0 = malloc_(0x700000);
    void* ros1 = malloc_(0x700000);

    if (ros0 == NULL || ros1 == NULL)
    {
        showMessageRaw("malloc fail!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return;
    }

	showMessageRaw("Reading ROS0", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    NorRead(0x0C0000, ros0, 0x700000);
	showMessageRaw("Reading ROS1", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
    NorRead(0x7C0000, ros1, 0x700000);

    if (memcmp(ros0, ros1, 0x700000))
    {
        showMessageRaw("ros compare fail!, please reinstall same firmware twice!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return;
    }

    free_(ros1);
    free_(ros0);
}


// XMB Options

// BadHTAB Testing
void badhtab_copy_log()
{
	read_write_generic_notify("/dev_hdd0/BadHTAB.txt", "/dev_usb000/BadHTAB.txt");
}

void badhtab_toggle_glitcher_test()
{
	toggle_generic("/dev_hdd0/BadHTAB_doGlitcherTest.txt", "Glitcher Test", 1);
}

void badhtab_toggle_skip_stage1()
{
	toggle_generic("/dev_hdd0/BadHTAB_doSkipStage1.txt", "Skip Stage 1", 1);
}

/*void badhtab_toggle_skip_stage_cfw()
{
	toggle_generic("/dev_hdd0/BadHTAB_doStage1_CFW.txt", "Skip Stage CFW", 1);
}*/

void badhtab_toggle_skip_stage2()
{
	toggle_generic("/dev_hdd0/BadHTAB_doSkipStage2.txt", "Skip Stage 2", 1);
}

void badhtab_toggle_skip_patch_more_lv1()
{
	toggle_generic("/dev_hdd0/BadHTAB_doSkipPatchMoreLv1.txt", "Skip Patch More LV1", 1);
}

void badhtab_toggle_lv1_dump()
{
	toggle_generic("/dev_hdd0/BadHTAB_doDumpLv1.txt", "BadHTAB LV1 Dump", 1);
}

void badhtab_toggle_lv1_dump_240m()
{
	toggle_generic("/dev_hdd0/BadHTAB_doDumpLv1_240M.txt", "BadHTAB LV1 Dump 240M", 1);
}

void badhtab_toggle_otheros()
{
	toggle_generic("/dev_hdd0/BadHTAB_doOtherOS.txt", "BadHTAB OtherOS", 1);
}

void badhtab_toggle_lv2_kernel_self()
{
	toggle_generic("/dev_hdd0/BadHTAB_doLoadLv2Kernel_Self.txt", "BadHTAB LV2 Kernel SELF", 1);
}

void badhtab_toggle_lv2_kernel_fself()
{
	toggle_generic("/dev_hdd0/BadHTAB_doLoadLv2Kernel_Fself.txt", "BadHTAB LV2 Kernel FSELF", 1);
}

// BadWDSD Testing
void badwdsd_copy_log()
{
	read_write_generic_notify("/dev_hdd0/BadWDSD.txt", "/dev_usb000/BadWDSD.txt");
}

void badwdsd_toggle_lv2_kernel_fself()
{
	toggle_generic("/dev_hdd0/BadWDSD_doLoadLv2Kernel_Fself.txt", "BadWDSD LV2 Kernel FSELF", 1);
}

void badwdsd_toggle_lv2_kernel_zfself()
{
	toggle_generic("/dev_hdd0/BadWDSD_doLoadLv2Kernel_ZFself.txt", "BadWDSD LV2 Kernel ZFSELF", 1);
}

void badwdsd_toggle_otheros_fself()
{
	toggle_generic("/dev_hdd0/BadWDSD_doOtherOS_Fself.txt", "BadWDSD OtherOS FSELF", 1);
}

void badwdsd_toggle_otheros_zfself()
{
	toggle_generic("/dev_hdd0/BadWDSD_doOtherOS_ZFself.txt", "BadWDSD OtherOS ZFSELF", 1);
}

void badwdsd_toggle_skip_ros_compare()
{
	toggle_generic("/dev_hdd0/BadWDSD_doSkipRosCompare.txt", "BadWDSD Skip ROS Compare", 1);
}

void badwdsd_toggle_flash_ros1()
{
	toggle_generic("/dev_hdd0/BadWDSD_doFlashRos1.txt", "BadWDSD Reflash ROS1", 1);
}
