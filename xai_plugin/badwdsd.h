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

bool IsFileExist(const char* path);
size_t GetFileSize(const char* path);
double GetFWVersion();

void lv1_read(uint64_t addr, uint64_t size, void *out_Buf);
void lv1_write(uint64_t addr, uint64_t size, const void *in_Buf);

uint8_t get_bank_indicator();
void set_bank_indicator(uint8_t value);
bool FlashIsNor();
bool TargetIsCEX();
bool TargetIsDEX();
bool TargetIsDECR();
uint8_t GetTarget();
const char* GetFlashType();
bool CheckFirmwareVersion();

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