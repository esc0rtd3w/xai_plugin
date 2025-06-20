#ifndef __BADWDSD_H__
#define __BADWDSD_H__

#define eieio()                \
	{                          \
		asm volatile("eieio"); \
		asm volatile("sync");  \
	}
#define isync() asm volatile("isync")

struct lv2_storage_device_info {
	uint8_t res1[32];
	uint32_t vendor_id;
	uint32_t device_id;
	uint64_t capacity;
	uint32_t sector_size;
	uint32_t media_count;
	uint8_t res2[8];
};

void patch_um(void);
void patch_um_eeprom(void);

bool IsFileExist(const char* path);
//size_t GetFileSize(FILE* f);
size_t GetFileSize(const char* path);
double GetFWVersion(void);

// BadHTAB Testing
void badhtab_copy_log();
void badhtab_toggle_glitcher_test();
void badhtab_toggle_skip_stage1();
//void badhtab_toggle_skip_stage_cfw();
void badhtab_toggle_skip_stage2();
void badhtab_toggle_skip_patch_more_lv1();
void badhtab_toggle_lv1_dump();
void badhtab_toggle_lv1_dump_240m();
void badhtab_toggle_otheros();
void badhtab_toggle_lv2_kernel_self();
void badhtab_toggle_lv2_kernel_fself();

// BadWDSD Testing
void badwdsd_copy_log();
void badwdsd_toggle_lv2_kernel_fself();
void badwdsd_toggle_lv2_kernel_zfself();
void badwdsd_toggle_otheros_fself();
void badwdsd_toggle_otheros_zfself();
void badwdsd_toggle_skip_ros_compare();
void badwdsd_toggle_flash_ros1();

void lv1_read(uint64_t addr, uint64_t size, void *out_Buf);
void lv1_write(uint64_t addr, uint64_t size, const void *in_Buf);

//static inline uint64_t lv1_read2(uint64_t addr);
//static inline void lv1_write2(uint64_t addr, uint64_t value);

uint8_t get_bank_indicator();
void set_bank_indicator(uint8_t value);
bool FlashIsNor();
bool TargetIsCEX();
bool TargetIsDEX();
bool TargetIsDECR();
uint8_t GetTarget();
const char* GetFlashType();
bool CheckFWVersion();

void NorWrite(uint64_t offset, const void* data, uint64_t size);
void NorRead(uint64_t offset, void* data, uint64_t size);
void BadWDSD_Write_Stagex();
void BadWDSD_Write_ros(bool compare, bool doFlashRos1);

bool IsExploited();
int InstallQCFW(bool doLegacy, bool doSkipRosCompare, bool doFlashRos1);
int InstallStagexOnly();
int InstallCoreOSOnly(bool doSkipRosCompare, bool doFlashRos1);
void VerifyQCFW(void);
void VerifyStagexOnly(void);
void VerifyCoreOSOnly(void);

// Individual function tests
void CompareROSBanks(void);

#endif __BADWDSD_H__