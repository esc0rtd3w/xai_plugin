/*
 *	From Habib Toolbox with some changes added
 *
 *	This file contains data for different versions of FW
 *	It is possible that support for some more may need to be added
 */

#include <stdio.h>
#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
#include "log.h"
#include "qa.h"
#include "hfw_settings.h"
#include "gccpch.h"
#include "hvcall.h"
#include "mm.h"
#include "cex2dex.h"
#include "eeprom.h"

static uint64_t um_ndpmo_eeprom_offset;
static uint64_t dm_patch1_offset, dm_patch2_offset, dm_patch3_offset, dm_patch4_offset;

static patches_eeprom patch_hv_checks[5] =
{	
	{ 0, 0x38000000ULL, 0xE8180008ULL },
	{ 0, 0x60000000ULL, 0xF8010098ULL },
	{ 0, 0x38600001ULL, 0x4BFFF0E5ULL },
	{ 0, 0x3BE00001ULL, 0x38A10070ULL },
	{ 0, 0x38600000ULL, 0x48006065ULL },
};

static uint8_t erk[0x20] = 
{
	0x34, 0x18, 0x12, 0x37, 0x62, 0x91, 0x37, 0x1c,
	0x8b, 0xc7, 0x56, 0xff, 0xfc, 0x61, 0x15, 0x25,
	0x40, 0x3f, 0x95, 0xa8, 0xef, 0x9d, 0x0c, 0x99,
	0x64, 0x82, 0xee, 0xc2, 0x16, 0xb5, 0x62, 0xed
};

static uint8_t hmac[0x40] = 
{
	0xcc, 0x30, 0xc4, 0x22, 0x91, 0x13, 0xdb, 0x25,
	0x73, 0x35, 0x53, 0xaf, 0xd0, 0x6e, 0x87, 0x62,
	0xb3, 0x72, 0x9d, 0x9e, 0xfa, 0xa6, 0xd5, 0xf3,
	0x5a, 0x6f, 0x58, 0xbf, 0x38, 0xff, 0x8b, 0x5f,
	0x58, 0xa2, 0x5b, 0xd9, 0xc9, 0xb5, 0x0b, 0x01,
	0xd1, 0xab, 0x40, 0x28, 0x67, 0x69, 0x68, 0xea,
	0xc7, 0xf8, 0x88, 0x33, 0xb6, 0x62, 0x93, 0x5d,
	0x75, 0x06, 0xa6, 0xb5, 0xe0, 0xf9, 0xd9, 0x7a
};

static uint8_t iv_qa[0x10] = 
{
	0xe8, 0x66, 0x3a, 0x69, 0xcd, 0x1a, 0x5c, 0x45,
	0x4a, 0x76, 0x1e, 0x72, 0x8c, 0x7c, 0x25, 0x4e
};

static void lv1_poked(uint64_t addr, uint64_t value)
{
	system_call_2(7, HV_BASE + addr, value);
}

static int lv1_patches()
{
	char patch_state[120];
	uint64_t ori_value;

	// Search offset in LV1
	um_ndpmo_eeprom_offset = findValueinLV1(0xFA000, 0xFF000, 0x7FC3F3784802D40DULL);
	if(!um_ndpmo_eeprom_offset)
		um_ndpmo_eeprom_offset = findValueinLV1(0x700000, 0x710000, 0x7FC3F3784802D40DULL);

	dm_patch1_offset = findValueinLV1(0x160000, 0x190000, 0x3BA1009048004EC5ULL);
	if(!dm_patch1_offset)
		dm_patch1_offset = findValueinLV1(0x160000, 0x190000, 0x3BA1009048004EC5ULL);

	patch_hv_checks[0].offset = um_ndpmo_eeprom_offset + 8;
	patch_hv_checks[1].offset = dm_patch1_offset + 0x14;
	patch_hv_checks[2].offset = dm_patch1_offset + 0x38;
	patch_hv_checks[3].offset = dm_patch1_offset + 0xB0;
	patch_hv_checks[4].offset = dm_patch1_offset + 0xB8;

	if(!um_ndpmo_eeprom_offset || !dm_patch1_offset)
		return 1;

	for(int i = 0; i <= 4; i++)
	{
		ori_value = lv1_peek32(patch_hv_checks[i].offset);

		sprintf_(patch_state, "Patching LV1: Offset 0x%X - Original: 0x%X - Patch: 0x%X\n", 
			(int)patch_hv_checks[i].offset, (int)ori_value, (int)patch_hv_checks[i].patch);

		log(patch_state);

		lv1_poke32(patch_hv_checks[i].offset, patch_hv_checks[i].patch);
	}

	return 0;
}

static void restore_patches()
{
	for(int i = 0; i <= 4; i++)
		lv1_poke32(patch_hv_checks[i].offset, patch_hv_checks[i].ori);
}

void read_qa_flag()
{
	uint8_t value = 0;
	update_mgr_read_eeprom(QA_FLAG_OFFSET, &value);

	showMessage((!value) ? "msg_qa_check_enabled" : "msg_qa_check_disabled", (char *)XAI_PLUGIN, (char *)TEX_INFO2);
}

int set_qa_flag(uint8_t value)
{
	uint8_t idps[IDPS_SIZE];
	uint8_t seed[TOKEN_SIZE];
	uint8_t token[TOKEN_SIZE];	

	if(receive_eid_idps((value == FULL ? EID0 : EID5), idps))
	{
		log("Unable to get IDPS from EID\n");
		return 5;
	}

	memset(seed, 0, TOKEN_SIZE);
	memcpy(seed + 4, idps, IDPS_SIZE);

	if(seed[0x04] != 0x00 && seed[0x05] != 0x00 && seed[0x06] != 0x00 && 
		seed[0x07] != 0x01 && seed[0x08] != 0x00 && seed[0x0A] != 0x00)
	{
		showMessage("msg_idps_not_valid", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		return 1;
	}	

	seed[3] = 1;

	if(value)
	{
		// Advanced QA Flags
		if(value == 2)
		{
			seed[21] |= 0x1;  // DEH_DEBUG_DISABLE 
			seed[21] |= 0x2;  // DEX_DEBUG_DISABLE 
			seed[21] |= 0x4;  // ALL_DEBUG_DISABLE 
			seed[21] |= 0x20; // CEX_BOOT_ENABLE

			seed[23] |= 0x1;  // DEH_DEBUG_DISABLE 
			seed[23] |= 0x2;  // DEX_DEBUG_DISABLE
			seed[23] |= 0x4;  // ALL_DEBUG_DISABLE 
			seed[23] |= 0x8;  // DEH_BOOT_ENABLE 
			seed[23] |= 0x10; // DEX_BOOT_ENABLE 
			seed[23] |= 0x20; // CEX_BOOT_ENABLE

			seed[51] |= 0x1; // QA_FLAG_ALLOW_NON_QA
			seed[51] |= 0x2; // QA_FLAG_FORCE_UPDATE
		}
		// Default
		else
		{
			seed[39] |= 0x1; // QA_FLAG_EXAM_API_ENABLE
			seed[39] |= 0x2; // QA_FLAG_QA_MODE_ENABLE

			seed[47] |= 0x2; // checked by lv2_kernel.self and sys_init_osd.self 
			seed[47] |= 0x4; // can run sys_init_osd.self from /app_home ?

			seed[51] |= 0x1; // QA_FLAG_ALLOW_NON_QA
			seed[51] |= 0x2; // QA_FLAG_FORCE_UPDATE
		}
	}

	sha1_hmac(seed + 60, seed, (uint32_t)60, hmac, (uint32_t)0x40);
	AesCbcCfbEncrypt(token, seed, 0x50, erk, 0x100, iv_qa);

	if(lv1_patches() != SUCCEEDED)
	{
		log("Unable to get data from LV1\nPlease contact Evilnat to add support for this FW\n");
		return 5;
	}

	struct ps3dm_scm_write_eeprom write_eeprom;
	int len;
	uint8_t *p = (uint8_t*)&write_eeprom;
	uint64_t laid, paid, vuart_lpar_addr, muid, nwritten;

	if(lv1_allocate_memory(4096, 0x0C, 0, &vuart_lpar_addr, &muid) != 0)
	{
		showMessage("msg_error_allocate_mem", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		restore_patches();
		return 2;
	}

	if(mm_map_lpar_memory_region(vuart_lpar_addr, HV_BASE, HV_SIZE, HV_PAGE_SIZE, 0) != 0)
	{
		showMessage("msg_error_map_mem", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		restore_patches();
		return 3;
	}

	laid = 0x1070000002000001ULL;
	paid = 0x1070000033000001ULL;

	memset(&write_eeprom, 0, sizeof(write_eeprom));

	ps3dm_init_header(&write_eeprom.dm_hdr, 1, PS3DM_FID_SCM,
		sizeof(write_eeprom)	-	sizeof(struct ps3dm_header),
		sizeof(write_eeprom)	-	sizeof(struct ps3dm_header));

	ps3dm_init_ss_header(&write_eeprom.ss_hdr, PS3DM_PID_SCM_WRITE_EEPROM, laid, paid);
	write_eeprom.offset = 0x48D3E;
	write_eeprom.nwrite = 0x50;
	write_eeprom.buf_size = 0x50;
	memset(write_eeprom.buf, 0, sizeof(write_eeprom.buf));
	memcpy(write_eeprom.buf, token, 0x50);
	len = sizeof(write_eeprom);		

	for(uint16_t n = 0; n < len ; n += 8)
	{
		static uint64_t value;
		memcpy(&value, &p[n], 8);
		lv1_poked((uint64_t) n, value);
		__asm__("sync");
		value =  lv2_peek(0x8000000000000000ULL);
	}	

	if(lv1_write_virtual_uart(10, vuart_lpar_addr, len, &nwritten) != 0)
	{
		showMessage("msg_error_write_uart", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
		restore_patches();
		return 4;
	}	

	update_mgr_write_eeprom(QA_FLAG_OFFSET, (value) ? 0x00 : 0xFF); 

	restore_patches();

	return SUCCEEDED;
}