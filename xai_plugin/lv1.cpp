#include "lv1.h"
#include "hfw_settings.h"
#include "hen.h"
#include "badwdsd.h"
#include "gccpch.h"
#include "functions.h"
#include "log.h"

int dump_lv1()
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

    final_offset = 0x1000000ULL;

    vsh_sprintf(lv_file, LV1_DUMP, platform_info[0], platform_info[1], platform_info[2] >> 4);  
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
        showMessageRaw("An error occurred while dumping LV1", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
        return 1;
    }

    cellFsChmod(dump_file_path, 0666);

    showMessageRaw("Dumping LV1, please wait...", (char*)XAI_PLUGIN, (char*)TEX_INFO2);

    // Quickest method to dump LV2 and LV1 through xai_plugin
    // Default method will take at least two minutes to dump LV2, and even more for LV1
    uint8_t *dump = (uint8_t *)malloc_(0x40000);
    memset(dump, 0, 0x40000);            

    for(uint64_t offset = start_offset; offset < max_offset; offset += 8)
    {
        // Use lv1_read to fetch data
        lv1_read(0x8000000000000000ULL + offset, 8, &offset_dumped);

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
                showMessageRaw("An error occurred while dumping LV1", (char*)XAI_PLUGIN, (char*)TEX_ERROR);        

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

    showMessageRaw(msgf("LV1 dumped in\n%s", dump_file_path), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
    buzzer(SINGLE_BEEP);

    return 0;
}

int dump_full_ram() {
    //#define CHUNK_SIZE    0x10000        // 64 KB
    #define CHUNK_SIZE    0x40000        // 256 KB
    #define FULL_RAM_SIZE 0x10000000ULL    // 256 MB

	uint8_t platform_info[0x18];
	system_call_1(387, (uint64_t)platform_info);

    char dump_file_path[120], lv_file[120];

	vsh_sprintf(lv_file, RAM_DUMP, platform_info[0], platform_info[1], platform_info[2] >> 4);  
    //vsh_sprintf(dump_file_path, "%s/%s", (int)TMP_FOLDER, (int)lv_file);
    vsh_sprintf(dump_file_path, "%s/%s", TMP_FOLDER, RAM_DUMP);

    // Check for an attached USB drive; if found, use its path instead.
    char usb[120];
    CellFsStat st;
    for (int i = 0; i < 8; i++) {
        vsh_sprintf(usb, "/dev_usb%03d", i);
        if (cellFsStat(usb, &st) == CELL_FS_SUCCEEDED) {
            vsh_sprintf(dump_file_path, "%s/%s", usb, RAM_DUMP);
            break;
        }
    }

    int fd;
    if (cellFsOpen(dump_file_path,  CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != CELL_FS_SUCCEEDED) {
        showMessageRaw(msgf("Failed to open dump file: %s", dump_file_path), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
        return 1;
    }
    cellFsChmod(dump_file_path, 0666);
    showMessageRaw("Starting full RAM dump", (char*)XAI_PLUGIN, (char*)TEX_INFO2);

    uint8_t *buffer = (uint8_t *)malloc_(CHUNK_SIZE);
    if (!buffer) {
        showMessageRaw("Memory allocation error", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
        cellFsClose(fd);
        return 1;
    }
    memset(buffer, 0, CHUNK_SIZE);

    uint64_t offset = 0;
    uint64_t nrw = 0;
    while (offset < FULL_RAM_SIZE) {
        // Use lv1_read to fetch the memory chunk
        lv1_read(0x8000000000000000ULL + offset, CHUNK_SIZE, buffer);

        if (cellFsWrite(fd, buffer, CHUNK_SIZE, &nrw) != CELL_FS_SUCCEEDED) {
            showMessageRaw(msgf("Error writing dump at offset 0x%llX", offset), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
            free_(buffer);
            cellFsClose(fd);
            return 1;
        }

        sys_timer_usleep(1000);
        offset += CHUNK_SIZE;
    }

    free_(buffer);
    cellFsClose(fd);
    showMessageRaw(msgf("Full RAM dump complete:\n%s", dump_file_path), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
    buzzer(SINGLE_BEEP);
    return 0;
}

// BadHTAB LV1 Testing
/*
uint64_t lv1_peek2(uint64_t addr) {
    if ((addr & 7ULL) == 0)
        return lv1_peek(addr);
    
    uint64_t aligned = addr & ~7ULL;
    int offset = addr & 7;
    uint64_t first  = lv1_peek(aligned);
    uint64_t second = lv1_peek(aligned + 8);
    
    int numFirstBytes = 8 - offset;
    uint64_t mask = (1ULL << (numFirstBytes * 8)) - 1;
    uint64_t part1 = first & mask;
    uint64_t part2 = second >> (numFirstBytes * 8);
    
    return (part1 << (offset * 8)) | part2;
}

void lv1_poke2(uint64_t addr, uint64_t val)
{
    // If address is already aligned, use the standard poke.
    if ((addr & 7ULL) == 0) {
        lv1_poke(addr, val);
        return;
    }

    // Calculate the aligned base address and the offset within it.
    uint64_t aligned = addr & ~7ULL;  // aligned address (multiple of 8)
    int r = addr & 7;                 // offset in bytes (1..7)
    int numFirst = 8 - r;             // number of bytes in the first word to update

    // Read the two aligned 64-bit words covering the region.
    uint64_t orig1 = lv1_peek(aligned);
    uint64_t orig2 = lv1_peek(aligned + 8);

    // For the first aligned word:
    // We want to replace its lower (numFirst*8) bits with the upper part of val.
    // Create a mask to isolate the lower numFirst bytes.
    uint64_t mask1 = (1ULL << (numFirst * 8)) - 1;
    // Extract from val the bits that should go into the first word.
    // (Shift val right by r bytes so that its upper (8 - r) bytes line up.)
    uint64_t A = val >> (r * 8);
    // Build the new first word by preserving the upper bytes and inserting A.
    uint64_t new1 = (orig1 & ~mask1) | (A & mask1);

    // For the second aligned word:
    // We want to replace its upper r bytes with the lower part of val.
    // Create a mask that isolates the upper r bytes.
    uint64_t mask2 = 0xFFFFFFFFFFFFFFFFULL << ((8 - r) * 8);
    // Extract the lower r bytes from val.
    uint64_t B = val & ((1ULL << (r * 8)) - 1);
    // Build the new second word:
    // Preserve the lower (8 - r) bytes of orig2 and insert B shifted into the upper r bytes.
    uint64_t new2 = (orig2 & ~mask2) | (B << ((8 - r) * 8));

    // Write back the modified aligned words.
    lv1_poke(aligned, new1);
    lv1_poke(aligned + 8, new2);
}
*/

// Patches the 64-bit word at addr only if (current & mask) equals (expected & mask).
// Then it writes (current & ~mask) | (patch & mask) to preserve any bytes outside the mask.
bool lv1_patch_pattern(uint64_t addr, uint64_t expected, uint64_t patch, uint64_t mask)
{
    uint64_t current = lv1_peek(addr);
    if ((current & mask) != (expected & mask))
    {
        return false;
    }
    
    // Construct the new value: preserve bytes outside the mask,
    // and use patch bytes for the masked part.
    uint64_t new_val = (current & ~mask) | (patch & mask);
    lv1_poke(addr, new_val);
    
    return (lv1_peek(addr) & mask) == (patch & mask);
}

bool test_lv1_peek()
{
	//uint64_t addr = 0x1130;
	uint64_t addr = 0x323740;// 0000000000323740  53 6F 6E 79 20 43 65 6C  Sony Cel
	uint64_t val = lv1_peek(addr);

	if (val != 0 && val != 0xFFFFFFFFFFFFFFFFULL)
	{
		showMessageRaw(msgf("lv1_peek() success\naddr: 0x%016llX\nval: 0x%016llX", addr, val), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
		return true;
	}
	else
	{
		showMessageRaw(msgf("lv1_peek() failed\naddr: 0x%016llX\nval: 0x%016llX", addr, val), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
}

bool test_lv1_peek32()
{
	//uint64_t addr = 0x1130;
	uint64_t addr = 0x323740;// 0000000000323740  53 6F 6E 79  Sony
	uint32_t val = lv1_peek32(addr);

	if (val != 0 && val != 0xFFFFFFF)
	{
		showMessageRaw(msgf("lv1_peek32() success\naddr: 0x%08X\nval: 0x%08X", addr, val), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
		return true;
	}
	else
	{
		showMessageRaw(msgf("lv1_peek32() failed\naddr: 0x%08X\nval: 0x%08X", addr, val), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
}

bool test_lv1_poke()
{
	//uint64_t addr = 0x1130;
	uint64_t addr = 0x323740;// 0000000000323740  53 6F 6E 79 20 43 65 6C  Sony Cel
	//uint64_t patch = 0x7C01012438000000ULL;
	uint64_t patch = 0x4141414142424242ULL;// 0x536F6E792043656CULL
	uint64_t original = lv1_peek(addr);
	
	lv1_poke(addr, patch);
	

	uint64_t verify = lv1_peek(addr);

	if (verify == patch)
	{
		showMessageRaw(msgf("lv1_poke() success\naddr: 0x%016llX\npatch: 0x%016llX\noriginal: 0x%016llX", addr, patch, original), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
		return true;
	}
	else
	{
		showMessageRaw(msgf("lv1_poke() failed\naddr: 0x%016llX\npatch: 0x%016llX\noriginal: 0x%016llX", addr, patch, original), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
}

bool test_lv1_poke32()
{
	//uint64_t addr = 0x1130;
	uint64_t addr = 0x323740;// 0000000000323740  53 6F 6E 7  Sony
	//uint32_t patch = 0x7C010124;
	uint32_t patch = 0x41414141;// 0x536F6E79
	//uint32_t patch2 = 0x42424242;// 0x2043656C
	uint32_t original = lv1_peek32(addr);
	
	lv1_poke32(addr, patch);
	

	uint32_t verify = lv1_peek32(addr);

	if (verify == patch)
	{
		showMessageRaw(msgf("lv1_poke32() success\naddr: 0x%08X\npatch: 0x%08X\noriginal: 0x%08X", addr, patch, original), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
		return true;
	}
	else
	{
		showMessageRaw(msgf("lv1_poke32() failed\naddr: 0x%08X\npatch: 0x%08X\noriginal: 0x%08X", addr, patch, original), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return false;
	}
}

int unmask_bootldr()
{
    uint64_t addr1 = 0x27B638;
    uint64_t addr2 = 0x27B640;

    uint64_t orig1 = 0x7C7F1B7839840200ULL;
    uint64_t orig2 = 0xF8010090FBC10070ULL;

    uint64_t patch1 = 0x7C7F1B7800000000ULL;
    uint64_t patch2 = 0x00000000FBC10070ULL;

    uint64_t full_mask = 0xFFFFFFFFFFFFFFFFULL;

    bool patch1_ok = lv1_patch_pattern(addr1, orig1, patch1, full_mask);
    bool patch2_ok = lv1_patch_pattern(addr2, orig2, patch2, full_mask);

    if (patch1_ok && patch2_ok)
    {
        showMessageRaw(msgf("Apply LV1 Patch 1: Unmask bootldr Success at 0x%016llX", lv1_peek(addr1)), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
        showMessageRaw(msgf("Apply LV1 Patch 2: Unmask bootldr Success at 0x%016llX", lv1_peek(addr2)), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
        return 0;
    }
    else
    {
        showMessageRaw(msgf("Apply LV1 Patch Failed at 0x%016llX\nval:0x%016llX", addr1, lv1_peek(addr1)), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
        showMessageRaw(msgf("Apply LV1 Patch Failed at 0x%016llX\nval:0x%016llX", addr2, lv1_peek(addr2)), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
        return 1;
    }
}

int toggle_lv1_patch(const char* name, uint64_t addr, uint64_t ovalue, uint64_t pvalue)
{
	uint64_t verify = 0;
	uint64_t cvalue = lv1_peek(addr);
	//showMessageRaw(msgf("Current Value 0x%016llX", cvalue), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	if(cvalue==ovalue)
	{
		lv1_poke(addr, pvalue);
		verify = lv1_peek(addr);
		if (verify == pvalue)
		{
			showMessageRaw(msgf("Apply LV1 Patch: %s Success\naddr: 0x%016llX\ncvalue: 0x%016llX\nverify: 0x%016llX", (char*)name, addr, cvalue, verify), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
			return 0;
		}
		else
		{
			showMessageRaw(msgf("Apply LV1 Patch: %s Failed\naddr: 0x%016llX\ncvalue: 0x%08X\nverify: 0x%016llX", (char*)name, addr, cvalue, verify), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}
	else
	{
		//showMessageRaw(msgf("Expected Original Value Not Found\naddr: 0x%016llX\ncvalue: 0x%08X\npvalue: 0x%016llX", (char*)name, addr, cvalue, ovalue), (char*)XAI_PLUGIN, (char*)TEX_WARNING);
	}

	if(cvalue==pvalue)
	{
		lv1_poke(addr, ovalue);
		verify = lv1_peek(addr);
		if (verify == ovalue)
		{
			showMessageRaw(msgf("Restore LV1 Patch: %s Success\naddr: 0x%016llX\ncvalue: 0x%016llX\nverify: 0x%016llX", (char*)name, addr, cvalue, verify), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
			return 0;
		}
		else
		{
			showMessageRaw(msgf("Restore LV1 Patch: %s Failed\naddr: 0x%016llX\ncvalue: 0x%016llX\nverify: 0x%016llX", (char*)name, addr, cvalue, verify), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}
	else
	{
		//showMessageRaw(msgf("Expected Patched Value Not Found\naddr: 0x%016llX\ncvalue: 0x%016llX\npvalue: 0x%016llX", (char*)name, addr, cvalue, pvalue), (char*)XAI_PLUGIN, (char*)TEX_WARNING);
	}
}

int toggle_lv1_patch32(const char* name, uint64_t addr, uint32_t ovalue, uint32_t pvalue)
{
	uint32_t verify = 0;
	uint32_t cvalue = lv1_peek32(addr);
	//showMessageRaw(msgf("Current Value 0x%08X", cvalue), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	if(cvalue==ovalue)
	{
		lv1_poke32(addr, pvalue);
		verify = lv1_peek32(addr);
		if (verify == pvalue)
		{
			showMessageRaw(msgf("Apply LV1 32-bit Patch: %s Success\naddr: 0x%08X\ncvalue: 0x%08X\nverify: 0x%08X", (char*)name, addr, cvalue, verify), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
			return 0;
		}
		else
		{
			showMessageRaw(msgf("Apply LV1 32-bit Patch: %s Failed\naddr: 0x%08X\ncvalue: 0x%08X\nverify: 0x%08X", (char*)name, addr, cvalue, verify), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}
	else
	{
		//showMessageRaw(msgf("Expected Original Value Not Found\naddr: 0x%08X\ncvalue: 0x%08X\npvalue: 0x%08X", (char*)name, addr, cvalue, ovalue), (char*)XAI_PLUGIN, (char*)TEX_WARNING);
	}

	if(cvalue==pvalue)
	{
		lv1_poke32(addr, ovalue);
		verify = lv1_peek32(addr);
		if (verify == ovalue)
		{
			showMessageRaw(msgf("Restore LV1 32-bit Patch: %s Success\naddr: 0x%08X\ncvalue: 0x%08X\nverify: 0x%08X", (char*)name, addr, cvalue, verify), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
			return 0;
		}
		else
		{
			showMessageRaw(msgf("Restore LV1 32-bit Patch: %s Failed\naddr: 0x%08X\ncvalue: 0x%08X\nverify: 0x%08X", (char*)name, addr, cvalue, verify), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return 1;
		}
	}
	else
	{
		//showMessageRaw(msgf("Expected Patched Value Not Found\naddr: 0x%08X\ncvalue: 0x%08X\npvalue: 0x%08X", (char*)name, addr, cvalue, pvalue), (char*)XAI_PLUGIN, (char*)TEX_WARNING);
	}
}

/*int lv1_peek_keyboard()
{
    uint64_t addr, value;
    // Prompt user for address input
    if(getHexInput("Enter hex address to peek:", &addr) != 0) {
         showMessageRaw(msgf("Failed to get address input."), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
         return -1;
    }
    // Call the low-level peek
    value = lv1_peek(addr);
    // Display the result
    showMessageRaw(msgf("Peek: addr: 0x%016llX, value: 0x%016llX", addr, value), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
    return 0;
}

int lv1_poke_keyboard()
{
    uint64_t addr, value, verify;
    // Prompt user for address input
    if(getHexInput("Enter hex address to poke:", &addr) != 0) {
         showMessageRaw(msgf("Failed to get address input."), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
         return -1;
    }
    // Prompt user for value input
    if(getHexInput("Enter hex value to poke:", &value) != 0) {
         showMessageRaw(msgf("Failed to get value input."), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
         return -1;
    }
    // Write the value
    lv1_poke(addr, value);
    // Verify the write by reading back the value
    verify = lv1_peek(addr);
    if(verify == value) {
         showMessageRaw(msgf("Poke: Success.\naddr: 0x%016llX, value: 0x%016llX", addr, verify), (char*)XAI_PLUGIN, (char*)TEX_SUCCESS);
         return 0;
    } else {
         showMessageRaw(msgf("Poke: Failed.\naddr: 0x%016llX, expected: 0x%016llX, got: 0x%016llX", addr, value, verify), (char*)XAI_PLUGIN, (char*)TEX_ERROR);
         return 1;
    }
}*/


#define USB_PATH    "/dev_usb000"
#define CHUNK_SZ    0x10000ULL
#define HV_BASE     0x8000000000000000ULL

//------------------------------------------------------------------------------
// Generic dumper: read HV @ (HV_BASE+phys) for 'size' bytes and write to USB_PATH/fname
//------------------------------------------------------------------------------
static int dump_hv_region(const char *fname, uint64_t phys, uint64_t size) {
    char path[128];
    vsh_sprintf(path, "%s/%s", USB_PATH, fname);

    int fd;
    if (cellFsOpen(path, CELL_FS_O_CREAT|CELL_FS_O_TRUNC|CELL_FS_O_RDWR, &fd, NULL, 0) != CELL_FS_SUCCEEDED) {
        showMessageRaw(msgf("OPEN_FAIL %s", path), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
        return -1;
    }
    cellFsChmod(path, 0666);

    uint8_t *buf = (uint8_t*)malloc_(CHUNK_SZ);
    if (!buf) {
        showMessageRaw("ALLOC_FAIL", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
        cellFsClose(fd);
        return -1;
    }

    uint64_t off = 0, written;
    while (off < size) {
        uint64_t chunk = (size - off > CHUNK_SZ) ? CHUNK_SZ : (size - off);
        lv1_read(HV_BASE + phys + off, chunk, buf);
        if (cellFsWrite(fd, buf, chunk, &written) != CELL_FS_SUCCEEDED) {
            showMessageRaw(msgf("WRITE_ERR @%llx", off), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
            break;
        }
        off += chunk;
        sys_timer_usleep(1000);
    }

    free_(buf);
    cellFsClose(fd);
    showMessageRaw(msgf("%s dumped %llx bytes", fname, size), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
    return 0;
}

//------------------------------------------------------------------------------
// 1) LV0 / LV1 / LV2
//------------------------------------------------------------------------------
int dump_lv0_code() {
    return dump_hv_region("hv_lv0_code.bin",
                          0x0000000000080000ULL, 0x0000000000020000ULL);
}
int dump_lv1_code() {
    return dump_hv_region("hv_lv1_code.bin",
                          0x0000000000200000ULL, 0x0000000000040000ULL);
}
int dump_lv2_region() {
    return dump_hv_region("hv_lv2_region.bin",
                          0x0000000008000000ULL, 0x0000000000800000ULL);
}

//------------------------------------------------------------------------------
// 2) SPE0–6 MMIO (base=0x20000000000 + idx*0x80000, size=0x80000)
//------------------------------------------------------------------------------
int dump_spe0_mmio() {
    return dump_hv_region("hv_spe0_mmio.bin",
                          0x00000020000000000ULL, 0x80000ULL);
}
int dump_spe1_mmio() {
    return dump_hv_region("hv_spe1_mmio.bin",
                          0x00000020000080000ULL, 0x80000ULL);
}
int dump_spe2_mmio() {
    return dump_hv_region("hv_spe2_mmio.bin",
                          0x00000020000100000ULL, 0x80000ULL);
}
int dump_spe3_mmio() {
    return dump_hv_region("hv_spe3_mmio.bin",
                          0x00000020000180000ULL, 0x80000ULL);
}
int dump_spe4_mmio() {
    return dump_hv_region("hv_spe4_mmio.bin",
                          0x00000020000200000ULL, 0x80000ULL);
}
int dump_spe5_mmio() {
    return dump_hv_region("hv_spe5_mmio.bin",
                          0x00000020000280000ULL, 0x80000ULL);
}
int dump_spe6_mmio() {
    return dump_hv_region("hv_spe6_mmio.bin",
                          0x00000020000300000ULL, 0x80000ULL);
}

/*int dump_spe_mmio(int idx) {
    static const uint64_t base[7] = {
        0x00000020000000000ULL,
        0x00000020000080000ULL,
        0x00000020000100000ULL,
        0x00000020000180000ULL,
        0x00000020000200000ULL,
        0x00000020000280000ULL,
        0x00000020000300000ULL
    };
    if (idx<0||idx>6) return -1;
    char fn[32]; vsh_sprintf(fn,"hv_spe%d_mmio.bin",idx);
    return dump_hv_region(fn, base[idx], 0x80000ULL);
}*/

//------------------------------------------------------------------------------
// 3) Pervasive Memory (0x20000509000, sz=0x1000)
//------------------------------------------------------------------------------
int dump_pervasive_mem() {
    return dump_hv_region("hv_pervasive_mem.bin",
                          0x00000020000509000ULL, 0x1000ULL);
}

//------------------------------------------------------------------------------
// 4) SPE1–6 Shadow Registers (each sz=0x1000 at given phys addrs)
//------------------------------------------------------------------------------
int dump_spe1_shadow() {
    return dump_hv_region("hv_spe1_shadow.bin",
                          0x0000002000050C000ULL, 0x1000ULL);
}
int dump_spe2_shadow() {
    return dump_hv_region("hv_spe2_shadow.bin",
                          0x00000020000514290ULL, 0x1000ULL);
}
int dump_spe3_shadow() {
    return dump_hv_region("hv_spe3_shadow.bin",
                          0x00000020000508A00ULL, 0x1000ULL);
}
int dump_spe4_shadow() {
    return dump_hv_region("hv_spe4_shadow.bin",
                          0x0000002000050B0F0ULL, 0x1000ULL);
}
int dump_spe5_shadow() {
    return dump_hv_region("hv_spe5_shadow.bin",
                          0x0000002000051FFC90ULL, 0x1000ULL);
}
int dump_spe6_shadow() {
    return dump_hv_region("hv_spe6_shadow.bin",
                          0x0000002000051AE5B0ULL, 0x1000ULL);
}

/*int dump_spe_shadow(int idx) {
    static const uint64_t addr[7] = {
        0ULL,
        0x0000002000050C000ULL,  // SPE1 @ …0C000
        0x00000020000514290ULL,  // SPE2 @ …4290
        0x00000020000508A00ULL,  // SPE3 @ …8A00
        0x0000002000050B0F0ULL,  // SPE4 @ …50F0
        0x0000002000051FFC90ULL, // SPE5 @ …FC90
        0x0000002000051AE5B0ULL  // SPE6 @ …E5B0
    };
    if (idx<1||idx>6) return -1;
    char fn[32]; vsh_sprintf(fn,"hv_spe%d_shadow.bin",idx);
    return dump_hv_region(fn, addr[idx], 0x1000ULL);
}*/

//------------------------------------------------------------------------------
// 5) XDR Memory Channel Sizes & Type (each sz=4)
//------------------------------------------------------------------------------
int dump_xdr_ch1_size() {
    return dump_hv_region("hv_xdr_ch1_sz.bin",
                          0x0000002000050A0C8ULL, 4ULL);
}
int dump_xdr_ch0_size() {
    return dump_hv_region("hv_xdr_ch0_sz.bin",
                          0x0000002000050A188ULL, 4ULL);
}
int dump_xdr_type() {
    return dump_hv_region("hv_xdr_type.bin",
                          0x0000002000050A210ULL, 4ULL);
}

//------------------------------------------------------------------------------
// 6) SB bus subsystem @0x24000000000 (no size → skip or set 0)
//------------------------------------------------------------------------------
int dump_sb_bus_base() {
    return dump_hv_region("hv_sb_bus_base.bin",
                          0x00000024000000000ULL, 0ULL);
}

// 6.a) SB devices @ offsets 0x2000…0x2C00 (sz=0x200)
int dump_sata1_regs()  { return dump_hv_region("hv_sata1_regs.bin",0x24000002000ULL,0x200ULL); }
int dump_sata2_regs()  { return dump_hv_region("hv_sata2_regs.bin",0x24000002200ULL,0x200ULL); }
int dump_usb1_regs()   { return dump_hv_region("hv_usb1_regs.bin", 0x24000002400ULL,0x200ULL); }
int dump_usb2_regs()   { return dump_hv_region("hv_usb2_regs.bin", 0x24000002600ULL,0x200ULL); }
int dump_gelic_regs()  { return dump_hv_region("hv_gelic_regs.bin",0x24000002800ULL,0x200ULL); }
int dump_encdec_regs() { return dump_hv_region("hv_encdec_regs.bin",0x24000002C00ULL,0x200ULL); }

// 6.b) SB external interrupt ctrl @0x24000008000 sz=0x1000
int dump_sb_ext_intc() { return dump_hv_region("hv_sb_ext_intc.bin",0x24000008000ULL,0x1000ULL); }

// 6.c) SB bus interrupt handler @0x24000008100 & 0x24000008104 (sz=4)
int dump_sb_int_hdl1() { return dump_hv_region("hv_sb_int_hdl1.bin",0x24000008100ULL,4ULL); }
int dump_sb_int_hdl2() { return dump_hv_region("hv_sb_int_hdl2.bin",0x24000008104ULL,4ULL); }

// 6.d) SB status/info @0x24000087000 (no size→0)
int dump_sb_status() { return dump_hv_region("hv_sb_status.bin",0x24000087000ULL,0ULL); }

//------------------------------------------------------------------------------
// 7) SYSCON offsets (all sz=4 unless noted)
//------------------------------------------------------------------------------
int dump_syscon_pkt_hdr() { return dump_hv_region("hv_syscon_pkt_hdr.bin",0x2400008C000ULL,4ULL); }
int dump_syscon_pkt_bdy() { return dump_hv_region("hv_syscon_pkt_bdy.bin",0x2400008C010ULL,4ULL); }
int dump_syscon_recv1()   { return dump_hv_region("hv_syscon_recv1.bin", 0x2400008CFF0ULL,4ULL); }
int dump_syscon_recv2()   { return dump_hv_region("hv_syscon_recv2.bin", 0x2400008CFF4ULL,4ULL); }
int dump_syscon_send_hdr(){ return dump_hv_region("hv_syscon_snd_hdr.bin",0x2400008D000ULL,4ULL); }
int dump_syscon_send_bdy(){ return dump_hv_region("hv_syscon_snd_bdy.bin",0x2400008D010ULL,4ULL); }
int dump_syscon_send1()   { return dump_hv_region("hv_syscon_snd1.bin", 0x2400008DFF0ULL,4ULL); }
int dump_syscon_send2()   { return dump_hv_region("hv_syscon_snd2.bin", 0x2400008DFF4ULL,4ULL); }
int dump_syscon_rcv3()    { return dump_hv_region("hv_syscon_rcv3.bin", 0x2400008E000ULL,4ULL); }
int dump_syscon_testbit() { return dump_hv_region("hv_syscon_testbit.bin",0x2400008E004ULL,4ULL); }
int dump_syscon_notify()  { return dump_hv_region("hv_syscon_notify.bin",0x2400008E100ULL,4ULL); }

//------------------------------------------------------------------------------
// 8) BAR‑spaced SB devices @0x24003000000… each sz=0x1000 unless noted
//------------------------------------------------------------------------------
int dump_sata1_bar()     { return dump_hv_region("hv_sata1_bar.bin",    0x24003000000ULL,0x1000ULL); }
int dump_sata2_bar()     { return dump_hv_region("hv_sata2_bar.bin",    0x24003001000ULL,0x1000ULL); }
int dump_gelic_bar()     { return dump_hv_region("hv_gelic_bar.bin",    0x24003004000ULL,0x1000ULL); }
int dump_encdec_bar()    { return dump_hv_region("hv_encdec_bar.bin",   0x24003005000ULL,0x1000ULL); }
int dump_encdec_test()   { return dump_hv_region("hv_encdec_test.bin",  0x24003005200ULL,4ULL); }
int dump_encdec_cmd()    { return dump_hv_region("hv_encdec_cmd.bin",   0x240030060A0ULL,4ULL); }

// 8.a) USB bar @0x24003010000/20000 sz=0x10000
int dump_usb1_bar()      { return dump_hv_region("hv_usb1_bar.bin",     0x24003010000ULL,0x10000ULL); }
int dump_usb2_bar()      { return dump_hv_region("hv_usb2_bar.bin",     0x24003020000ULL,0x10000ULL); }

//------------------------------------------------------------------------------
// 9) SB SATA/USB repeats @0x24003800000… 
//------------------------------------------------------------------------------
int dump_sata1_bar2()    { return dump_hv_region("hv_sata1_bar2.bin",   0x24003800000ULL,0x1000ULL); }
int dump_sata2_bar2()    { return dump_hv_region("hv_sata2_bar2.bin",   0x24003801000ULL,0x1000ULL); }
int dump_sata1_bar3()    { return dump_hv_region("hv_sata1_bar3.bin",   0x24003802000ULL,0x1000ULL); }
int dump_sata2_bar3()    { return dump_hv_region("hv_sata2_bar3.bin",   0x24003803000ULL,0x1000ULL); }
int dump_usb1_bar2()     { return dump_hv_region("hv_usb1_bar2.bin",    0x24003810000ULL,0x10000ULL); }
int dump_usb2_bar2()     { return dump_hv_region("hv_usb2_bar2.bin",    0x24003820000ULL,0x10000ULL); }

//------------------------------------------------------------------------------
// 10) NOR Flash @0x2401F000000 sz=0x1000000
//------------------------------------------------------------------------------
int dump_nor_flash()     { return dump_hv_region("hv_nor_flash.bin",   0x2401F000000ULL,0x1000000ULL); }
// 10.a) SYS ROM @0x2401FC00000 sz=0x40000
int dump_sys_rom()       { return dump_hv_region("hv_sys_rom.bin",     0x2401FC00000ULL,0x40000ULL); }

//------------------------------------------------------------------------------
// 11) AV Manager (/dev/ioif0) @0x28000000000 sz=0x2000
//------------------------------------------------------------------------------
int dump_avmngr_regs1()  { return dump_hv_region("hv_avmngr1.bin",    0x28000000000ULL,0x2000ULL); }
// 11.a) AV Manager @0x28001800000 sz=0x1000
int dump_avmngr_regs2()  { return dump_hv_region("hv_avmngr2.bin",    0x28001800000ULL,0x1000ULL); }
// 11.b) AV OutCtrl @0x28000600000 sz=0x4000
int dump_av_outctrl()    { return dump_hv_region("hv_av_outctrl.bin",  0x28000600000ULL,0x4000ULL); }
// 11.c) AV PLL Ctrl @0x28000680000 sz=0x4000
int dump_av_pllctrl()    { return dump_hv_region("hv_av_pllctrl.bin",  0x28000680000ULL,0x4000ULL); }
// 11.d) AV other regs...
int dump_av_misc1()      { return dump_hv_region("hv_av_misc1.bin",    0x28000080000ULL,0x8000ULL); }
int dump_av_misc2()      { return dump_hv_region("hv_av_misc2.bin",    0x28000088000ULL,0x1000ULL); }
int dump_av_misc3()      { return dump_hv_region("hv_av_misc3.bin",    0x2800000C000ULL,0x1000ULL); }
int dump_av_misc4()      { return dump_hv_region("hv_av_misc4.bin",    0x2800008A000ULL,0x1000ULL); }
int dump_av_misc5()      { return dump_hv_region("hv_av_misc5.bin",    0x2800008C000ULL,0x1000ULL); }

//------------------------------------------------------------------------------
// 12) GPU Device Memory Regions
//------------------------------------------------------------------------------
int dump_gpu_mem1()      { return dump_hv_region("hv_gpu_mem1.bin",   0x28080000000ULL,0xFE00000ULL); }
int dump_gpu_mem2()      { return dump_hv_region("hv_gpu_mem2.bin",   0x00000000003C0000ULL,0xC000ULL); }
int dump_gpu_mem3()      { return dump_hv_region("hv_gpu_mem3.bin",   0x2808FE00000ULL,0x40000ULL); }
int dump_gpu_mem4()      { return dump_hv_region("hv_gpu_mem4.bin",   0x28000C00000ULL,0x20000ULL); }
int dump_gpu_mem5()      { return dump_hv_region("hv_gpu_mem5.bin",   0x28000080100ULL,0x8000ULL); }

//------------------------------------------------------------------------------
// 13) RSX / RAMIN / GRAPH
//------------------------------------------------------------------------------
int dump_rsx_intstate()  { return dump_hv_region("hv_rsx_intst.bin",  0x2808FC00000ULL,0x400000ULL); }
int dump_ramin_all()     { return dump_hv_region("hv_ramin_all.bin",  0x2808FF80000ULL,0x80000ULL); }
int dump_ramin_hash()    { return dump_hv_region("hv_ramin_hash.bin", 0x2808FF90000ULL,0x4000ULL); }
int dump_ramin_fifo()    { return dump_hv_region("hv_ramin_fifo.bin", 0x2808FFA0000ULL,0x1000ULL); }
int dump_dma_objs()      { return dump_hv_region("hv_dma_objs.bin",   0x2808FFC0000ULL,0x10000ULL); }
int dump_graph_objs()    { return dump_hv_region("hv_graph_objs.bin", 0x2808FFD0000ULL,0x10000ULL); }
int dump_graph_ctx()     { return dump_hv_region("hv_graph_ctx.bin",  0x2808FFE0000ULL,0x10000ULL); }

//------------------------------------------------------------------------------
// 14) GameOS regions / HTAB
//------------------------------------------------------------------------------
int dump_gameos0()       { return dump_hv_region("hv_gameos0.bin",    0x0000000000000000ULL,0x1000000ULL); }
int dump_gameos1()       { return dump_hv_region("hv_gameos1.bin",    0x700020000000ULL,   0xA0000ULL); }
int dump_gameos2()       { return dump_hv_region("hv_gameos2.bin",    0x700020000000ULL,   0xE900000ULL); }
int dump_gameos_htab()   { return dump_hv_region("hv_gameos_htab.bin",0x800000000F000000ULL,0x40000ULL); }

//------------------------------------------------------------------------------
// 15) All‑in‑one dumper
//------------------------------------------------------------------------------
int dump_all_regions() {
    dump_lv0_code();
	dump_lv1_code();
	dump_lv2_region();
    //for(int i=0;i<=6;i++) dump_spe_mmio(i);
	dump_spe0_mmio();
	dump_spe1_mmio();
	dump_spe2_mmio();
	//dump_spe3_mmio();// crashes
	dump_spe4_mmio();
	dump_spe5_mmio();
	dump_spe6_mmio();
    dump_pervasive_mem();
    //for(int i=1;i<=6;i++) dump_spe_shadow(i);
	dump_spe1_shadow();
	dump_spe2_shadow();
	dump_spe3_shadow();
	dump_spe4_shadow();
	dump_spe5_shadow();
	dump_spe6_shadow();
    dump_xdr_ch1_size();
	dump_xdr_ch0_size();
	dump_xdr_type();
    dump_sb_bus_base();
    dump_sata1_regs();
	dump_sata2_regs();
	dump_usb1_regs();
	dump_usb2_regs();
    dump_gelic_regs();
	dump_encdec_regs();
	dump_sb_ext_intc();
    dump_sb_int_hdl1();
	dump_sb_int_hdl2();
	dump_sb_status();
    dump_syscon_pkt_hdr();
	dump_syscon_pkt_bdy();
	dump_syscon_recv1();
	dump_syscon_recv2();
    dump_syscon_send_hdr();
	dump_syscon_send_bdy();
	dump_syscon_send1();
	dump_syscon_send2();
    dump_syscon_rcv3();
	dump_syscon_testbit();
	dump_syscon_notify();
    dump_sata1_bar();
	dump_sata2_bar();
	dump_gelic_bar();
	dump_encdec_bar();
    dump_encdec_test();
	dump_encdec_cmd();
	dump_usb1_bar();
	dump_usb2_bar();
    dump_sata1_bar2();
	dump_sata2_bar2();
	dump_sata1_bar3();
	dump_sata2_bar3();
    dump_usb1_bar2();
	dump_usb2_bar2();
	//dump_nor_flash();// crashes
	//dump_sys_rom();// crashes
    dump_avmngr_regs1();
	dump_avmngr_regs2();
	dump_av_outctrl();
	dump_av_pllctrl();
    dump_av_misc1();
	dump_av_misc2();
	dump_av_misc3();
	dump_av_misc4();
	dump_av_misc5();
    dump_gpu_mem1();
	dump_gpu_mem2();
	dump_gpu_mem3();
	dump_gpu_mem4();
	dump_gpu_mem5();
    dump_rsx_intstate();
	dump_ramin_all();
	dump_ramin_hash();
	dump_ramin_fifo();
    dump_dma_objs();
	dump_graph_objs();
	dump_graph_ctx();
    dump_gameos0();
	//dump_gameos1();// crashes
	dump_gameos2();
	dump_gameos_htab();
    return 0;
}

// LV1 Patches
void toggle_lv1_patch_unmask_bootldr()
{
	toggle_lv1_patch("Unmask bootldr", 0x27B630, 0x39840200f8010090ULL, 0x0000000000000000ULL);
}

void toggle_lv1_patch_test1()
{
	toggle_lv1_patch("Patch #1", 0x323740, 0x536F6E792043656CULL, 0x4141414142424242ULL);

	//toggle_lv1_patch("Patch #1", 0x3B1890, 0x0100000046726920ULL, 0x0100000047726920ULL);
	//toggle_lv1_patch("Patch #2", 0x3B1898, 0x4170722031362032ULL, 0x4270722031362032ULL);
	//toggle_lv1_patch("Patch #3", 0x3B18A0, 0x303A31373A323320ULL, 0x313A31373A323320ULL);
	//toggle_lv1_patch("Patch #4", 0x3B18A8, 0x3230313000000000ULL, 0x3230333000000000ULL);

	//lv1_patch_pattern(0x3B1890, 0x0100000046726920ULL, 0x0100000047726920ULL, 0xFFFFFFFFFFFFFFFFULL);// 0100000046726920
	//lv1_patch_pattern(0x3B1894, 0x4170722031362032ULL, 0x4270722031362032ULL, 0xFFFFFFFFFFFFFFFFULL);// 4170722031362032
	//lv1_patch_pattern(0x3B1894, 0x303A31373A323320ULL, 0x313A31373A323320ULL, 0xFFFFFFFFFFFFFFFFULL);// 303A31373A323320
	//lv1_patch_pattern(0x3B1894, 0x0100000046726920ULL, 0x0100000047726920ULL, 0xFFFFFFFFFFFFFFFFULL);// 3230313000000000
}

void toggle_lv1_patch_test2()
{
	toggle_lv1_patch32("Patch #1", 0x323740, 0x536F6E79, 0x41414141);
	toggle_lv1_patch32("Patch #2", 0x323744, 0x2043656C, 0x42424242);

	//toggle_lv1_patch32("Patch #1", 0x3B1894, 0x46726920, 0x57656420);
	//toggle_lv1_patch32("Patch #2", 0x3B1898, 0x41707220, 0x4D617920);
	//toggle_lv1_patch32("Patch #3", 0x3B189C, 0x31362032, 0x30342031);
	//toggle_lv1_patch32("Patch #4", 0x3B18A0, 0x303A3137, 0x323A3131);
	//toggle_lv1_patch32("Patch #5", 0x3B18A4, 0x3A323320, 0x3A313020);
	//toggle_lv1_patch32("Patch #6", 0x3B18A8, 0x32303130, 0x32303235);
}
