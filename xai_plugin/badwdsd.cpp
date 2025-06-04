#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
//#include <sys/fs_external.h>
#include <sys/timer.h>
#include "badwdsd.h"
#include "functions.h"
#include "gccpch.h"
#include "log.h"
#include "hfw_settings.h"

bool IsFileExist(const char* path)
{
    CellFsStat stat;
    int rc = cellFsStat(path, &stat);
    return (rc == CELL_OK);
}

size_t GetFileSize(const char* path)
{
    CellFsStat stat;
    int rc = cellFsStat(path, &stat);
    if (rc != CELL_OK)
        return 0;
    return stat.st_size;
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
		showMessage("IsExploited: false", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
		return false;
	}

	/*res = lv1_unmap_physical_address_region(lpar_addr);

	if (res != 0)
	{
		showMessage(msgf("lv1_unmap_physical_address_region failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return false;
	}*/

	showMessage("IsExploited: true", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return true;
}

uint8_t get_bank_indicator()
{
	uint8_t value = 0x99;

	int32_t res = update_mgr_read_eeprom(0x48c24, &value);

	if (res != 0)
	{
		showMessage(msgf("update_mgr_read_eeprom failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return 0x99;
	}

	return value;
}

void set_bank_indicator(uint8_t value)
{
	int32_t res = update_mgr_write_eeprom(0x48c24, value);

	if (res != 0)
	{
		showMessage(msgf("update_mgr_write_eeprom failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return;
	}
}

bool FlashIsNor()
{
	uint8_t flag;

	int32_t res = lv2_ss_get_cache_of_flash_ext_flag(&flag);

	if (res != 0)
	{
		showMessage(msgf("lv2_storage_get_cache_of_flash_ext_flag failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return false;
	}

	// bit 0 set means NAND; cleared means NOR
	showMessage(msgf("lv2_storage_get_cache_of_flash_ext_flag, res = %d, flag = 0x%02x\n", res, (uint32_t)flag), (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return !(flag & 0x1);
}

bool TargetIsCEX()
{
	uint64_t type;

	int32_t res = lv2_dbg_get_console_type(&type);

	if (res != 0)
	{
		showMessage(msgf("lv2_dbg_get_console_type failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return false;
	}

	showMessage(msgf("lv2_dbg_get_console_type = 1, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return (type == 1);
}

bool TargetIsDEX()
{
	uint64_t type;

	int32_t res = lv2_dbg_get_console_type(&type);

	if (res != 0)
	{
		showMessage(msgf("lv2_dbg_get_console_type failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return false;
	}
	
	showMessage(msgf("lv2_dbg_get_console_type = 2, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return (type == 2);
}

bool TargetIsDECR()
{
	uint64_t type;

	int32_t res = lv2_dbg_get_console_type(&type);

	if (res != 0)
	{
		showMessage(msgf("lv2_dbg_get_console_type failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return false;
	}
	
	showMessage(msgf("lv2_dbg_get_console_type = 3, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	return (type == 3);
}

void NorWrite(uint64_t offset, const void* data, uint64_t size)
{
	const uint8_t* dataa = (const uint8_t*)data;

	showMessage(msgf("NorWrite() offset = 0x%lx, data = 0x%lx, size = %lu\n", offset, (uint64_t)data, size), (char *)XAI_PLUGIN, (char *)TEX_INFO);

	if (data == NULL)
		return;

	if (size == 0)
		return;

	if (!FlashIsNor())
	{
		showMessage("Flash is not nor!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return;
	}

	int32_t res;

	uint32_t unknown2;

	uint64_t dev_id = 0x100000000000004ull;
	uint64_t dev_flags = 0x22ull;

	static const uint64_t sector_size = 512;
	uint64_t burst_size = (512 * sector_size);

	showMessage(msgf("burst_size = %lu\n", burst_size), (char *)XAI_PLUGIN, (char *)TEX_INFO);

	uint32_t dev_handle;

	res = lv2_storage_open(dev_id, &dev_handle);

	if (res != 0)
	{
		showMessage(msgf("lv2_storage_open failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return;
	}

	char* buf = (char*)malloc_(burst_size);

	if (buf == NULL)
	{
		showMessage("malloc failed!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
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

		showMessage(msgf("curOffset = 0x%lx, curDataOffset = 0x%lx, processSize = %lu, zzz = %lu, yyy = %lu, xxx = %lu, sector_idx = %lu, left = %lu\n",
			curOffset, curDataOffset, processSize, zzz, yyy, xxx, sector_idx, left), (char *)XAI_PLUGIN, (char *)TEX_INFO);

		if (burst_size > left)
		{
			while (burst_size > left)
				burst_size -= sector_size;

			showMessage(msgf("burst_size = %lu\n", burst_size), (char *)XAI_PLUGIN, (char *)TEX_INFO);
		}

		if ((zzz != 0) || (processSize != sector_size))
		{
			showMessage("1\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessage(msgf("lv2_storage_read failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

				//abort();
				return;
			}

			memcpy(&buf[zzz], &dataa[curDataOffset], xxx);

			res = lv2_storage_write(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessage(msgf("lv2_storage_write failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

				//abort();
				return;
			}

			curOffset += xxx;
			curDataOffset += xxx;

			left -= xxx;
		}
		else if ((burst_size > 0) && (left >= burst_size) && ((burst_size % sector_size) == 0))
		{
			showMessage("2\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

			memcpy(&buf[0], &dataa[curDataOffset], burst_size);

			res = lv2_storage_write(dev_handle, 0, sector_idx, (burst_size / sector_size), buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessage(msgf("lv2_storage_write failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

				//abort();
				return;
			}

			curOffset += burst_size;
			curDataOffset += burst_size;

			left -= burst_size;
		}
		else
		{
			showMessage("3\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

			memcpy(&buf[0], &dataa[curDataOffset], processSize);

			res = lv2_storage_write(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessage(msgf("lv2_storage_write failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

				//abort();
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
		showMessage(msgf("lv2_storage_close failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return;
	}

	free_(buf);

	showMessage("NorWrite() done.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
}

void NorRead(uint64_t offset, void* data, uint64_t size)
{
	uint8_t* dataa = (uint8_t*)data;

	showMessage(msgf("NorRead() offset = 0x%lx, data = 0x%lx, size = %lu\n", offset, (uint64_t)data, size), (char *)XAI_PLUGIN, (char *)TEX_INFO);

	if (data == NULL)
		return;

	if (size == 0)
		return;

	if (!FlashIsNor())
	{
		showMessage("Flash is not nor!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return;
	}

	int32_t res;

	uint32_t unknown2;

	uint64_t dev_id = 0x100000000000004ull;
	uint64_t dev_flags = 0x22ull;

	static const uint64_t sector_size = 512;
	uint64_t burst_size = (512 * sector_size);

	showMessage(msgf("burst_size = %lu\n", burst_size), (char *)XAI_PLUGIN, (char *)TEX_INFO);

	uint32_t dev_handle;

	res = lv2_storage_open(dev_id, &dev_handle);

	if (res != 0)
	{
		showMessage(msgf("lv2_storage_open failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return;
	}

	char* buf = (char*)malloc_(burst_size);

	if (buf == NULL)
	{
		showMessage("malloc failed!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
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

		showMessage(msgf("curOffset = 0x%lx, curDataOffset = 0x%lx, processSize = %lu, zzz = %lu, yyy = %lu, xxx = %lu, sector_idx = %lu, left = %lu\n",
			curOffset, curDataOffset, processSize, zzz, yyy, xxx, sector_idx, left), (char *)XAI_PLUGIN, (char *)TEX_INFO);

		if (burst_size > left)
		{
			while (burst_size > left)
				burst_size -= sector_size;

			showMessage(msgf("burst_size = %lu\n", burst_size), (char *)XAI_PLUGIN, (char *)TEX_INFO);
		}

		if ((zzz != 0) || (processSize != sector_size))
		{
			showMessage("1\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessage(msgf("lv2_storage_read failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

				//abort();
				return;
			}

			memcpy(&dataa[curDataOffset], &buf[zzz], xxx);

			curOffset += xxx;
			curDataOffset += xxx;

			left -= xxx;
		}
		else if ((burst_size > 0) && (left >= burst_size) && ((burst_size % sector_size) == 0))
		{
			showMessage("2\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

			res = lv2_storage_read(dev_handle, 0, sector_idx, (burst_size / sector_size), buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessage(msgf("lv2_storage_read failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

				//abort();
				return;
			}

			memcpy(&dataa[curDataOffset], &buf[0], burst_size);

			curOffset += burst_size;
			curDataOffset += burst_size;

			left -= burst_size;
		}
		else
		{
			showMessage("3\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

			res = lv2_storage_read(dev_handle, 0, sector_idx, 1, buf, &unknown2, dev_flags);

			if (res != 0)
			{
				showMessage(msgf("lv2_storage_read failed! res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

				//abort();
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
		showMessage(msgf("lv2_storage_close failed!, res = %d\n", res), (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return;
	}

	free_(buf);

	showMessage("NorRead() done.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
}

void BadWDSD_Write_Stagex()
{
    showMessage("BadWDSD_Write_Stagex()\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

    if (!FlashIsNor())
    {
        showMessage("Flash is not nor!!!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

        //abort();
        return;
    }

    int fd = -1;
    int rc;

    if (fd < 0)
    {
        showMessage("Loading /app_home/Stagex.bin\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

        rc = cellFsOpen("/app_home/Stagex.bin", CELL_FS_O_RDONLY, &fd, NULL, 0);

        if (rc != CELL_OK)
            showMessage("Not found\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
    }

    if (fd < 0)
    {
        showMessage("Loading /dev_hdd0/Stagex.bin\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

        rc = cellFsOpen("/dev_hdd0/Stagex.bin", CELL_FS_O_RDONLY, &fd, NULL, 0);

        if (rc != CELL_OK)
            showMessage("Not found\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
    }

    if (fd < 0)
    {
        showMessage("Stagex.bin not found!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

        //abort();
        return;
    }

    CellFsStat stat;
    rc = cellFsFstat(fd, &stat);
    size_t size = (rc == CELL_OK) ? stat.st_size : 0;
    showMessage(msgf("size = %lu\n", size), (char *)XAI_PLUGIN, (char *)TEX_INFO);

    void* code = malloc_(size);
    uint64_t bytesRead;
    cellFsRead(fd, code, size, &bytesRead);

    cellFsClose(fd);

    showMessage(msgf("code = 0x%lx\n", (uint64_t)code), (char *)XAI_PLUGIN, (char *)TEX_INFO);

    if (size > (48 * 1024))
    {
        showMessage("size is too big!!!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

        //abort();
        return;
    }

    showMessage("Writing to flash...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    // lv1_write(0x2401F031000, size, code);
    NorWrite(0x31000, code, size);

    {
        showMessage(msgf("0x%lx\n", lv1_peek(0x2401F0002000ULL)), (char *)XAI_PLUGIN, (char *)TEX_INFO);
        showMessage(msgf("0x%lx\n", lv1_peek(0x2401F0310000ULL)), (char *)XAI_PLUGIN, (char *)TEX_INFO);
    }

    free_(code);
    showMessage("BadWDSD_Write_Stagex() done,\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
}

void BadWDSD_Write_ros(bool compare, bool doFlashRos1)
{
    showMessage("BadWDSD_Write_ros()\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

    if (!FlashIsNor())
    {
        showMessage("Flash is not nor!!!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

        //abort();
        return;
    }

    int fd = -1;
    int rc;

    if (fd < 0)
    {
        showMessage("Loading /app_home/CoreOS.bin\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

        rc = cellFsOpen("/app_home/CoreOS.bin", CELL_FS_O_RDONLY, &fd, NULL, 0);

        if (rc != CELL_OK)
            showMessage("Not found\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
    }

    if (fd < 0)
    {
        showMessage("Loading /dev_hdd0/CoreOS.bin\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

        rc = cellFsOpen("/dev_hdd0/CoreOS.bin", CELL_FS_O_RDONLY, &fd, NULL, 0);

        if (rc != CELL_OK)
            showMessage("Not found\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
    }

    if (fd < 0)
    {
        showMessage("CoreOS.bin not found!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

        //abort();
        return;
    }

    CellFsStat stat;
    rc = cellFsFstat(fd, &stat);
    size_t size = (rc == CELL_OK) ? stat.st_size : 0;
    showMessage(msgf("size = %lu\n", size), (char *)XAI_PLUGIN, (char *)TEX_INFO);

    void* code = malloc_(size);
    uint64_t bytesRead;
    cellFsRead(fd, code, size, &bytesRead);

    cellFsClose(fd);

    showMessage(msgf("code = 0x%lx\n", (uint64_t)code), (char *)XAI_PLUGIN, (char *)TEX_INFO);

    if (size > 0x700000)
    {
        showMessage("size is too big!!!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

        //abort();
        return;
    }

    if (compare)
    {
        showMessage("Comparing ros...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

        void* ros0 = malloc_(0x700000);
        void* ros1 = malloc_(0x700000);

        if (ros0 == NULL || ros1 == NULL)
        {
            showMessage("malloc fail!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

            //abort();

            return;
        }

        NorRead(0x0C0000, ros0, 0x700000);
        NorRead(0x7C0000, ros1, 0x700000);

        if (memcmp(ros0, ros1, 0x700000))
        {
            showMessage("ros compare fail!, please reinstall same firmware twice!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

            //abort();
            return;
        }

        free_(ros1);
        free_(ros0);
    }
	
    //showMessage(msgf("Writing to flash (%s)...\n", doFlashRos1 ? "ros1" : "ros0"), (char *)XAI_PLUGIN, (char *)TEX_INFO);
	const char* banksel = doFlashRos1 ? "ros1" : "ros0";
    showMessage(msgf("Writing to flash (%s)...\n", (char*)banksel), (char *)XAI_PLUGIN, (char *)TEX_INFO);
    NorWrite(doFlashRos1 ? 0x7C0000 : 0x0C0000, code, size);

    {
        showMessage(msgf("0x%lx\n", lv1_peek(0x2401F0002000ULL)), (char *)XAI_PLUGIN, (char *)TEX_INFO);
        showMessage(msgf("0x%lx\n", lv1_peek(0x2401F0310000ULL)), (char *)XAI_PLUGIN, (char *)TEX_INFO);
    }

    free_(code);
    showMessage("BadWDSD_Write_ros() done.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
}

double GetFWVersion()
{
    int32_t fd, rc = cellFsOpen("/dev_flash/vsh/etc/version.txt", CELL_FS_O_RDONLY, &fd, NULL, 0);
    if (rc != CELL_OK)
	{
        return 0.0;
	}

    char bufs[64];
    uint64_t len = 0;
    rc = cellFsRead(fd, bufs, sizeof(bufs) - 1, &len);
    cellFsClose(fd);
    if (rc != CELL_OK || len < 14)  // need at least "release:0X.XX00:"
	{
        return 0.0;
	}

    bufs[len] = '\0';

    // buf layout: "release:0X.XX00:"
    char* p = bufs + 8;  // points at '0'
    int ip = (p[0] - '0') * 10 + (p[1] - '0');
    int fp = (p[3] - '0') * 10 + (p[4] - '0');

	double version = (double)ip + ((double)fp / 100.0);

    char msg[64];
    vsh_sprintf(msg, "Firmware Version: %.2f\n", version);
    showMessage(msgf("%s", msg), (char *)XAI_PLUGIN, (char *)TEX_INFO);

    return version;
}

// BadWDSD/qCFW Installer
// returns 1 on success, 0 on failure
int InstallQCFW(bool doLegacy, bool doSkipRosCompare, bool doFlashRos1)
{
	if (GetFWVersion() < 4.70)
	{
		showMessage("firmware not supported!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return 0;
	}

	sys_timer_sleep(3);// DEBUG sleep

	//showMessage(msgf("Flash is %s\n", FlashIsNor() ? "NOR" : "NAND"), (char *)XAI_PLUGIN, (char *)TEX_INFO);
	const char* flashtype = (FlashIsNor() ? "NOR" : "NAND");
    showMessage(msgf("Flash is %s\n", (char*)flashtype), (char *)XAI_PLUGIN, (char *)TEX_INFO);

	sys_timer_sleep(3);

	if (TargetIsCEX())
	{
		showMessage("Target is CEX\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
	}
	else if (TargetIsDEX())
	{
		showMessage("Target is DEX\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
	}
	else if (TargetIsDECR())
	{
		showMessage("Target is DECR\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
	}
	else
	{
		showMessage("Unknown target!!!\n", (char *)XAI_PLUGIN, (char *)TEX_WARNING);
		return 0;
	}

	showMessage("DEBUG: Writing Stagex will begin in 30 seconds\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
	sys_timer_sleep(30);// DEBUG sleep

    if (!doLegacy)
    {
        showMessage("Installing Stagex.bin...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
        //BadWDSD_Write_Stagex();
		showMessage("DEBUG: BadWDSD_Write_Stagex() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
        showMessage("Stagex.bin installed.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

        showMessage("Installing CoreOS.bin...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

        if (!IsExploited())
        {
            showMessage("You MUST be exploited at this point!\nInstall modchip first!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
            // abort();
            return 0;
        }

        uint8_t bank_indicator = get_bank_indicator();
        showMessage(msgf("bank_indicator = 0x%x\n", (uint32_t)bank_indicator), (char *)XAI_PLUGIN, (char *)TEX_INFO);

        if (bank_indicator != 0x00)
        {
            showMessage("Please reinstall firmware ONCE again then try again.\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
            // abort();
            return 0;
        }
		
		showMessage("DEBUG: Writing CoreOS will begin in 30 seconds\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
		sys_timer_sleep(30);// DEBUG sleep

        //BadWDSD_Write_ros(false, false);
		showMessage("DEBUG: BadWDSD_Write_ros() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

        set_bank_indicator(0xff);
        bank_indicator = get_bank_indicator();
        showMessage(msgf("bank_indicator = 0x%x\n", (uint32_t)bank_indicator), (char *)XAI_PLUGIN, (char *)TEX_INFO);

        if (bank_indicator != 0xff)
        {
            showMessage("Bank switch failed!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
            // abort();
            return 0;
        }

        showMessage("CoreOS.bin installed.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    }
    else
    {
        // legacy install
        showMessage("Legacy install\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
        //BadWDSD_Write_Stagex();
        //BadWDSD_Write_ros(!doSkipRosCompare, doFlashRos1);
		showMessage("DEBUG: BadWDSD_Write_Stagex() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
		showMessage("DEBUG: BadWDSD_Write_ros() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    }

	showMessage("DEBUG: return 1\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
	
    sys_timer_sleep(5);
	VerifyQCFW();

    return 1;
}

// writes only the Stagex.bin payload
// returns 1 on success, 0 on failure
int InstallStagexOnly()
{
	if (GetFWVersion() < 4.70)
	{
		showMessage("firmware not supported!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return 0;
	}

	sys_timer_sleep(3);// DEBUG sleep

    showMessage("DEBUG: Writing Stagex will begin in 30 seconds\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    sys_timer_sleep(30);

    showMessage("Installing Stagex.bin...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    //BadWDSD_Write_Stagex();
	showMessage("DEBUG: BadWDSD_Write_Stagex() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    showMessage("Stagex.bin installed.\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

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
	if (GetFWVersion() < 4.70)
	{
		showMessage("firmware not supported!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

		//abort();
		return 0;
	}
	
	sys_timer_sleep(3);// DEBUG sleep

    showMessage("Installing CoreOS.bin...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    if (!IsExploited())
    {
        showMessage("You MUST be exploited at this point!\nInstall modchip first!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return 0;
    }

    uint8_t bank_indicator = get_bank_indicator();
    showMessage(msgf("bank_indicator = 0x%x\n", (uint32_t)bank_indicator), (char *)XAI_PLUGIN, (char *)TEX_INFO);
    if (bank_indicator != 0x00)
    {
        showMessage("Please reinstall firmware ONCE again then try again.\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return 0;
    }

    showMessage("DEBUG: Writing CoreOS will begin in 30 seconds\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    sys_timer_sleep(30);

    //BadWDSD_Write_ros(!doSkipRosCompare, doFlashRos1);
	showMessage("DEBUG: BadWDSD_Write_ros() is disabled for testing\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

    set_bank_indicator(0xff);
    bank_indicator = get_bank_indicator();
    showMessage(msgf("bank_indicator = 0x%x\n", (uint32_t)bank_indicator), (char *)XAI_PLUGIN, (char *)TEX_INFO);
    if (bank_indicator != 0xff)
    {
        showMessage("Bank switch failed!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return 0;
    }

    showMessage("CoreOS.bin installed.\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
	
    sys_timer_sleep(5);
	VerifyCoreOSOnly();

    return 1;
}

void VerifyQCFW(void)
{
	showMessage("VerifyQCFW: Not Yet Implemented", (char *)XAI_PLUGIN, (char *)TEX_INFO);
}

void VerifyStagexOnly(void)
{
	showMessage("VerifyStagexOnly: Not Yet Implemented", (char *)XAI_PLUGIN, (char *)TEX_INFO);
}

void VerifyCoreOSOnly(void)
{
	showMessage("VerifyCoreOSOnly: Not Yet Implemented", (char *)XAI_PLUGIN, (char *)TEX_INFO);
}

void CompareROSBanks(void)
{
    showMessage("Comparing ros...\n", (char *)XAI_PLUGIN, (char *)TEX_INFO);

    void* ros0 = malloc_(0x700000);
    void* ros1 = malloc_(0x700000);

    if (ros0 == NULL || ros1 == NULL)
    {
        showMessage("malloc fail!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);

        //abort();

        return;
    }

	showMessage("Reading ROS0", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    NorRead(0x0C0000, ros0, 0x700000);
	showMessage("Reading ROS1", (char *)XAI_PLUGIN, (char *)TEX_INFO);
    NorRead(0x7C0000, ros1, 0x700000);

    if (memcmp(ros0, ros1, 0x700000))
    {
        showMessage("ros compare fail!, please reinstall same firmware twice!\n", (char *)XAI_PLUGIN, (char *)TEX_ERROR);
        return;
    }

    free_(ros1);
    free_(ros0);
}

