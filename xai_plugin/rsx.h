#ifndef __RSX_H__
#define __RSX_H__

#include "hen.h"


// RSX Overclocking
void get_rsx_clock_speeds(void);
void TestRsxClockSettings();
void TestRsxClockSettingsSafe();

void apply_rsx_clock(uint64_t core, uint64_t mem);
void apply_rsx_mem_clock(uint64_t mem_mhz);
void apply_rsx_core_clock(uint64_t core_mhz);

void SetRsxClockSpeed(uint32_t core_freq, uint32_t mem_freq);
void SetRsxCoreClockSpeed(uint32_t core_freq);
void SetRsxMemoryClockSpeed(uint32_t mem_freq);

void OverclockGpuCoreTest();
void OverclockGpuMemTest();

// Matched Speeds
void set_rsx_clock_100_100();
void set_rsx_clock_150_150();
void set_rsx_clock_200_200();
void set_rsx_clock_250_250();
void set_rsx_clock_300_300();
void set_rsx_clock_350_350();
void set_rsx_clock_400_400();
void set_rsx_clock_450_450();
void set_rsx_clock_500_500();
void set_rsx_clock_550_550();
void set_rsx_clock_600_600();
void set_rsx_clock_650_650();
void set_rsx_clock_700_700();
void set_rsx_clock_750_750();
void set_rsx_clock_800_800();
void set_rsx_clock_850_850();
void set_rsx_clock_900_900();
void set_rsx_clock_950_950();
void set_rsx_clock_1000_1000();

// Core-Only Speeds
void set_rsx_clock_100_650();
void set_rsx_clock_150_650();
void set_rsx_clock_200_650();
void set_rsx_clock_250_650();
void set_rsx_clock_300_650();
void set_rsx_clock_350_650();
void set_rsx_clock_400_650();
void set_rsx_clock_450_650();
void set_rsx_clock_500_650();
void set_rsx_clock_550_650();
void set_rsx_clock_600_650();
//void set_rsx_clock_650_650();// Duplicate
void set_rsx_clock_700_650();
void set_rsx_clock_750_650();
void set_rsx_clock_800_650();
void set_rsx_clock_850_650();
void set_rsx_clock_900_650();
void set_rsx_clock_950_650();
void set_rsx_clock_1000_650();

// Memory Only Speeds
void set_rsx_clock_500_100();
void set_rsx_clock_500_150();
void set_rsx_clock_500_200();
void set_rsx_clock_500_250();
void set_rsx_clock_500_300();
void set_rsx_clock_500_350();
void set_rsx_clock_500_400();
void set_rsx_clock_500_450();
//void set_rsx_clock_500_500();// Duplicate
void set_rsx_clock_500_550();
void set_rsx_clock_500_600();
//void set_rsx_clock_500_650();// Duplicate
void set_rsx_clock_500_700();
void set_rsx_clock_500_750();
void set_rsx_clock_500_800();
void set_rsx_clock_500_850();
void set_rsx_clock_500_900();
void set_rsx_clock_500_950();
void set_rsx_clock_500_1000();

void set_rsx_core_clock_100(void);
void set_rsx_core_clock_150(void);
void set_rsx_core_clock_200(void);
void set_rsx_core_clock_250(void);
void set_rsx_core_clock_300(void);
void set_rsx_core_clock_350(void);
void set_rsx_core_clock_400(void);
void set_rsx_core_clock_450(void);
void set_rsx_core_clock_500(void);
void set_rsx_core_clock_550(void);
void set_rsx_core_clock_600(void);
void set_rsx_core_clock_650(void);
void set_rsx_core_clock_700(void);
void set_rsx_core_clock_750(void);
void set_rsx_core_clock_800(void);
void set_rsx_core_clock_850(void);
void set_rsx_core_clock_900(void);
void set_rsx_core_clock_950(void);
void set_rsx_core_clock_1000(void);

void set_rsx_mem_clock_100(void);
void set_rsx_mem_clock_125(void);
void set_rsx_mem_clock_150(void);
void set_rsx_mem_clock_175(void);
void set_rsx_mem_clock_200(void);
void set_rsx_mem_clock_225(void);
void set_rsx_mem_clock_250(void);
void set_rsx_mem_clock_275(void);
void set_rsx_mem_clock_300(void);
void set_rsx_mem_clock_325(void);
void set_rsx_mem_clock_350(void);
void set_rsx_mem_clock_375(void);
void set_rsx_mem_clock_400(void);
void set_rsx_mem_clock_425(void);
void set_rsx_mem_clock_450(void);
void set_rsx_mem_clock_475(void);
void set_rsx_mem_clock_500(void);
void set_rsx_mem_clock_525(void);
void set_rsx_mem_clock_550(void);
void set_rsx_mem_clock_575(void);
void set_rsx_mem_clock_600(void);
void set_rsx_mem_clock_625(void);
void set_rsx_mem_clock_650(void);
void set_rsx_mem_clock_675(void);
void set_rsx_mem_clock_700(void);
void set_rsx_mem_clock_725(void);
void set_rsx_mem_clock_750(void);
void set_rsx_mem_clock_775(void);
void set_rsx_mem_clock_800(void);
void set_rsx_mem_clock_825(void);
void set_rsx_mem_clock_850(void);
void set_rsx_mem_clock_875(void);
void set_rsx_mem_clock_900(void);
void set_rsx_mem_clock_925(void);
void set_rsx_mem_clock_950(void);
void set_rsx_mem_clock_975(void);
void set_rsx_mem_clock_1000(void);

#endif __RSX_H__