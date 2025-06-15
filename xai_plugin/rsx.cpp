#include "rsx.h"
#include "hfw_settings.h"
#include "hen.h"
#include "badwdsd.h"
#include "gccpch.h"
#include "functions.h"
#include "log.h"

void get_rsx_clock_speeds()
{
	clock_s clock;

    // Read core multiplier
    clock.value = lv1_peek(0x28000004028ULL);
    //clock.value = lv1_read2(0x28000004028ULL);
    uint8_t core_mul = clock.mul;
    uint32_t core_mhz = core_mul * 50;

    // Read memory multiplier
    clock.value = lv1_peek(0x28000004010ULL);
    //clock.value = lv1_read2(0x28000004010ULL);
    uint8_t mem_mul = clock.mul;
    uint32_t mem_mhz = mem_mul * 25;

    showMessageRaw(msgf( "RSX Core Clock: %u MHz (Mul=0x%x)\nRSX Memory Clock: %u MHz (Mul=0x%x)", core_mhz, core_mul, mem_mhz,  mem_mul), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void apply_rsx_clock(uint64_t core, uint64_t mem)
{
	// apply core
 
	clock_s clock;
	clock.value = lv1_peek(0x28000004028ULL);
	//clock.value = lv1_read2(0x28000004028ULL);
 
	clock.mul = (core / 50);
 
	lv1_poke(0x28000004028ULL, clock.value);
	//lv1_write2(0x28000004028ULL, clock.value);
	eieio();
 
	sys_timer_usleep(500000);// 500ms
 
	// apply mem
 
	{
		uint8_t target_mul = (mem / 25);
 
		clock_s clock;
		clock.value = lv1_peek(0x28000004010ULL);
		//clock.value = lv1_read2(0x28000004010ULL);
 
		bool up = (target_mul > clock.mul);
 
		while (clock.mul != target_mul)
		{
			// must apply slowly in 25mhz step, wait, repeat until reach target
 
			clock.mul += up ? 1 : -1;
 
			lv1_poke(0x28000004010ULL, clock.value);
			//lv1_write2(0x28000004010ULL, clock.value);
			eieio();
 
			sys_timer_usleep(200000);// 200ms
 
			showMessageRaw(msgf("%lx\n", (uint64_t)clock.mul), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
		}
	}
}

void apply_rsx_core_clock(uint64_t core_mhz)
{
    clock_s clock;
    // read current core‐clock register
    clock.value = lv1_peek(0x28000004028ULL);
    //clock.value = lv1_read2(0x28000004028ULL);
	
    // calculate and set new multiplier
    clock.mul   = (core_mhz / 50);
    lv1_poke(0x28000004028ULL, clock.value);
    //lv1_write2(0x28000004028ULL, clock.value);
    eieio();
    // give it a moment to take effect
    sys_timer_usleep(500000);// 500ms
    showMessageRaw(msgf("RSX Core Multiplier → 0x%x (%u MHz)\n", clock.mul, clock.mul * 25), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void apply_rsx_mem_clock(uint64_t mem_mhz)
{
    // compute target multiplier
    uint8_t target_mul = (mem_mhz / 25);

    clock_s clock;
    // read current memory‐clock register
    clock.value = lv1_peek(0x28000004010ULL);
    //clock.value = lv1_read2(0x28000004010ULL);

    // decide ramp direction
    bool up = (target_mul > clock.mul);

    // step one 25 MHz increment at a time until we hit target
    while (clock.mul != target_mul) {
        clock.mul += up ? +1 : -1;
        lv1_poke(0x28000004010ULL, clock.value);
        //lv1_write2(0x28000004010ULL, clock.value);
        eieio();
        sys_timer_usleep(200000);// 200ms
        showMessageRaw(msgf("RSX Memory Multiplier → 0x%x (%u MHz)\n", clock.mul, clock.mul * 25), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
    }
}

void OverclockGpuCoreTest()
{
	clock_s clock;
	lv1_read(0x2800000402CULL, 4, &clock.value);
	showMessageRaw(msgf("gpu core clock = 0x%x\n", (uint32_t)clock.mul), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	clock.mul = 0x02; // 100 MHz
	lv1_write(0x2800000402CULL, 4, &clock.value);

	lv1_read(0x2800000402CULL, 4, &clock.value);
	showMessageRaw(msgf("gpu core clock = 0x%x\n", (uint32_t)clock.mul), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void OverclockGpuMemTest()
{
	clock_s clock;
	lv1_read(0x28000004014ULL, 4, &clock.value);
	showMessageRaw(msgf("gpu memory clock = 0x%x\n", (uint32_t)clock.mul), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

	clock.mul = 0x1A; // 650 MHz
	lv1_write(0x28000004014ULL, 4, &clock.value);

	lv1_read(0x28000004014ULL, 4, &clock.value);
	showMessageRaw(msgf("gpu memory clock = 0x%x\n", (uint32_t)clock.mul), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void SetRsxClockSpeed(uint32_t core_freq, uint32_t mem_freq) {
    clock_s clock;

    // Validate core frequency, it should be in 50 MHz steps between 100 MHz and 1 GHz
    if (core_freq < 100 || core_freq > 1000 || core_freq % 50 != 0) {
        showMessageRaw(msgf("Invalid core frequency, must be between 100 MHz and 1 GHz in 50 MHz steps."), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
        return;
    }

    // Validate memory frequency, it should be in 25 MHz steps between 100 MHz and 1 GHz
    if (mem_freq < 100 || mem_freq > 1000 || mem_freq % 25 != 0) {
        showMessageRaw(msgf("Invalid memory frequency, must be between 100 MHz and 1 GHz in 25 MHz steps."), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
        return;
    }

    // Core clock multiplier: 50 MHz steps
    uint8_t core_mul = (core_freq / 50);

    // Memory clock multiplier: 25 MHz steps
    uint8_t mem_mul = (mem_freq / 25);

    // Set the GPU core clock
    //lv1_read(0x2800000402CULL, 4, &clock.value);
    clock.mul = core_mul;
    lv1_write(0x2800000402CULL, 4, &clock.value);
    //lv1_read(0x2800000402CULL, 4, &clock.value);

    // Set the GPU memory clock
    //lv1_read(0x28000004014ULL, 4, &clock.value);
    clock.mul = mem_mul;
    lv1_write(0x28000004014ULL, 4, &clock.value);
    //lv1_read(0x28000004014ULL, 4, &clock.value);
    
    showMessageRaw(msgf("RSX Core Clock: %d MHz / 0x%x\nRSX Memory Clock: %d MHz/ 0x%x", core_freq, core_mul, mem_freq, mem_mul), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void SetRsxCoreClockSpeed(uint32_t core_freq) {
    clock_s clock;

    // Validate core frequency, it should be in 50 MHz steps between 100 MHz and 1 GHz
    if (core_freq < 100 || core_freq > 1000 || core_freq % 50 != 0) {
        showMessageRaw("Invalid core frequency, must be between 100 MHz and 1 GHz in 50 MHz steps.", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
        return;
    }

    // Core clock multiplier: 50 MHz steps
    uint8_t core_mul = (core_freq / 50);

    // Set the GPU core clock
    //lv1_read(0x2800000402CULL, 4, &clock.value);
    clock.mul = core_mul;
    lv1_write(0x2800000402CULL, 4, &clock.value);
    //lv1_read(0x2800000402CULL, 4, &clock.value);
    
    showMessageRaw(msgf("RSX Core Clock: %d MHz / 0x%x", core_freq, core_mul), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void SetRsxMemoryClockSpeed(uint32_t mem_freq) {
    clock_s clock;

    // Validate memory frequency, it should be in 25 MHz steps between 100 MHz and 1 GHz
    if (mem_freq < 100 || mem_freq > 1000 || mem_freq % 25 != 0) {
        showMessageRaw("Invalid memory frequency, must be between 100 MHz and 1 GHz in 25 MHz steps.", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
        return;
    }

    // Memory clock multiplier: 25 MHz steps
    uint8_t mem_mul = (mem_freq / 25);

    // Set the GPU memory clock
    //lv1_read(0x28000004014ULL, 4, &clock.value);
    clock.mul = mem_mul;
    lv1_write(0x28000004014ULL, 4, &clock.value);
    //lv1_read(0x28000004014ULL, 4, &clock.value);
    
    showMessageRaw(msgf("RSX Memory Clock: %d MHz/ 0x%x", mem_freq, mem_mul), (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void TestRsxClockSettings() {
    uint32_t core_freqs[] = {100, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000}; // Core frequencies (50 MHz steps)
    uint32_t mem_freqs[] = {100, 125, 150, 175, 200, 225, 250, 275, 300, 325, 350, 375, 400, 425, 450, 475, 500, 525, 550, 575, 600, 625, 650, 675, 700, 725, 750, 775, 800, 825, 850, 875, 900, 925, 950, 975, 1000}; // Memory frequencies (25 MHz steps)

    showMessageRaw("Test RSX Clock Settings [100MHz - 1Ghz]", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
    sys_timer_usleep(3000000);

    // Start at 100 MHz and 100 MHz, then 100 MHz and 125 MHz, and so on.
    // This loop goes through core_freqs sequentially and pairs them with increasing memory_freqs
    int core_idx = 0;
    for (int i = 0; i < sizeof(mem_freqs) / sizeof(mem_freqs[0]); i++) {
        for (int j = core_idx; j < sizeof(core_freqs) / sizeof(core_freqs[0]); j++) {
            apply_rsx_clock(core_freqs[j], mem_freqs[i]);

            showMessageRaw(msgf("Setting RSX Core Clock to %d MHz and Memory Clock to %d MHz", core_freqs[j], mem_freqs[i]), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

            sys_timer_usleep(10000000);

            // After setting, move to the next memory frequency for the current core
            if (i == sizeof(mem_freqs) / sizeof(mem_freqs[0]) - 1) {
                core_idx++; // Move to the next core frequency after we've cycled through all memory frequencies
            }
        }
    }
    showMessageRaw("Test completed! All settings applied.", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}

void TestRsxClockSettingsSafe() {
    uint32_t core_freqs[] = {550, 600, 650, 650, 650, 700, 700, 700, 750, 750, 750, 800, 800, 800, 850, 850, 850, 900, 900, 950};
    uint32_t mem_freqs[] = {700, 750, 800, 850, 875, 850, 900, 925, 900, 950, 1000, 950, 975, 1000, 950, 975, 1000, 975, 1000, 1000};
    
    showMessageRaw("Test RSX Clock Settings [SAFE VALUES]", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
    sys_timer_usleep(3000000);

    for (int i = 0; i < sizeof(core_freqs) / sizeof(core_freqs[0]); i++) {
        uint32_t core_freq = core_freqs[i];
        uint32_t mem_freq = mem_freqs[i];
		
        //SetRsxClockSpeed(core_freq, mem_freq);
        apply_rsx_clock(core_freq, mem_freq);

        showMessageRaw(msgf("Setting RSX Core Clock to %d MHz and Memory Clock to %d MHz", core_freq, mem_freq), (char*)XAI_PLUGIN, (char*)TEX_INFO2);

        sys_timer_usleep(10000000);
    }
    showMessageRaw("Test completed! All settings applied.", (char*)XAI_PLUGIN, (char*)TEX_INFO2);
}



// Default Speed
//void set_rsx_clock_defaults()   { SetRsxClockSpeed(500, 650); }
void set_rsx_clock_defaults()   { apply_rsx_clock(500, 650); }

// Matched Speeds
/*void set_rsx_clock_100_100()    { SetRsxClockSpeed(100, 100); }
void set_rsx_clock_150_150()    { SetRsxClockSpeed(150, 150); }
void set_rsx_clock_200_200()    { SetRsxClockSpeed(200, 200); }
void set_rsx_clock_250_250()    { SetRsxClockSpeed(250, 250); }
void set_rsx_clock_300_300()    { SetRsxClockSpeed(300, 300); }
void set_rsx_clock_350_350()    { SetRsxClockSpeed(350, 350); }
void set_rsx_clock_400_400()    { SetRsxClockSpeed(400, 400); }
void set_rsx_clock_450_450()    { SetRsxClockSpeed(450, 450); }
void set_rsx_clock_500_500()    { SetRsxClockSpeed(500, 500); }
void set_rsx_clock_550_550()    { SetRsxClockSpeed(550, 550); }
void set_rsx_clock_600_600()    { SetRsxClockSpeed(600, 600); }
void set_rsx_clock_650_650()    { SetRsxClockSpeed(650, 650); }
void set_rsx_clock_700_700()    { SetRsxClockSpeed(700, 700); }
void set_rsx_clock_750_750()    { SetRsxClockSpeed(750, 750); }
void set_rsx_clock_800_800()    { SetRsxClockSpeed(800, 800); }
void set_rsx_clock_850_850()    { SetRsxClockSpeed(850, 850); }
void set_rsx_clock_900_900()    { SetRsxClockSpeed(900, 900); }
void set_rsx_clock_950_950()    { SetRsxClockSpeed(950, 950); }
void set_rsx_clock_1000_1000()  { SetRsxClockSpeed(1000, 1000); }*/

void set_rsx_clock_100_100()    { apply_rsx_clock(100, 100); }
void set_rsx_clock_150_150()    { apply_rsx_clock(150, 150); }
void set_rsx_clock_200_200()    { apply_rsx_clock(200, 200); }
void set_rsx_clock_250_250()    { apply_rsx_clock(250, 250); }
void set_rsx_clock_300_300()    { apply_rsx_clock(300, 300); }
void set_rsx_clock_350_350()    { apply_rsx_clock(350, 350); }
void set_rsx_clock_400_400()    { apply_rsx_clock(400, 400); }
void set_rsx_clock_450_450()    { apply_rsx_clock(450, 450); }
void set_rsx_clock_500_500()    { apply_rsx_clock(500, 500); }
void set_rsx_clock_550_550()    { apply_rsx_clock(550, 550); }
void set_rsx_clock_600_600()    { apply_rsx_clock(600, 600); }
void set_rsx_clock_650_650()    { apply_rsx_clock(650, 650); }
void set_rsx_clock_700_700()    { apply_rsx_clock(700, 700); }
void set_rsx_clock_750_750()    { apply_rsx_clock(750, 750); }
void set_rsx_clock_800_800()    { apply_rsx_clock(800, 800); }
void set_rsx_clock_850_850()    { apply_rsx_clock(850, 850); }
void set_rsx_clock_900_900()    { apply_rsx_clock(900, 900); }
void set_rsx_clock_950_950()    { apply_rsx_clock(950, 950); }
void set_rsx_clock_1000_1000()  { apply_rsx_clock(1000, 1000); }

// Core Only Speeds (mem fixed at 650)
/*void set_rsx_clock_100_650()    { SetRsxClockSpeed(100, 650); }
void set_rsx_clock_150_650()    { SetRsxClockSpeed(150, 650); }
void set_rsx_clock_200_650()    { SetRsxClockSpeed(200, 650); }
void set_rsx_clock_250_650()    { SetRsxClockSpeed(250, 650); }
void set_rsx_clock_300_650()    { SetRsxClockSpeed(300, 650); }
void set_rsx_clock_350_650()    { SetRsxClockSpeed(350, 650); }
void set_rsx_clock_400_650()    { SetRsxClockSpeed(400, 650); }
void set_rsx_clock_450_650()    { SetRsxClockSpeed(450, 650); }
void set_rsx_clock_500_650()    { SetRsxClockSpeed(500, 650); }
void set_rsx_clock_550_650()    { SetRsxClockSpeed(550, 650); }
void set_rsx_clock_600_650()    { SetRsxClockSpeed(600, 650); }
void set_rsx_clock_650_650()    { SetRsxClockSpeed(650, 650); }
void set_rsx_clock_700_650()    { SetRsxClockSpeed(700, 650); }
void set_rsx_clock_750_650()    { SetRsxClockSpeed(750, 650); }
void set_rsx_clock_800_650()    { SetRsxClockSpeed(800, 650); }
void set_rsx_clock_850_650()    { SetRsxClockSpeed(850, 650); }
void set_rsx_clock_900_650()    { SetRsxClockSpeed(900, 650); }
void set_rsx_clock_950_650()    { SetRsxClockSpeed(950, 650); }
void set_rsx_clock_1000_650()   { SetRsxClockSpeed(1000, 650); }*/

// Memory Only Speeds (core fixed at 500)
/*void set_rsx_clock_500_100()    { SetRsxClockSpeed(500, 100); }
void set_rsx_clock_500_150()    { SetRsxClockSpeed(500, 150); }
void set_rsx_clock_500_200()    { SetRsxClockSpeed(500, 200); }
void set_rsx_clock_500_250()    { SetRsxClockSpeed(500, 250); }
void set_rsx_clock_500_300()    { SetRsxClockSpeed(500, 300); }
void set_rsx_clock_500_350()    { SetRsxClockSpeed(500, 350); }
void set_rsx_clock_500_400()    { SetRsxClockSpeed(500, 400); }
void set_rsx_clock_500_450()    { SetRsxClockSpeed(500, 450); }
void set_rsx_clock_500_500()    { SetRsxClockSpeed(500, 500); }
void set_rsx_clock_500_550()    { SetRsxClockSpeed(500, 550); }
void set_rsx_clock_500_600()    { SetRsxClockSpeed(500, 600); }
void set_rsx_clock_500_650()    { SetRsxClockSpeed(500, 650); }
void set_rsx_clock_500_700()    { SetRsxClockSpeed(500, 700); }
void set_rsx_clock_500_750()    { SetRsxClockSpeed(500, 750); }
void set_rsx_clock_500_800()    { SetRsxClockSpeed(500, 800); }
void set_rsx_clock_500_850()    { SetRsxClockSpeed(500, 850); }
void set_rsx_clock_500_900()    { SetRsxClockSpeed(500, 900); }
void set_rsx_clock_500_950()    { SetRsxClockSpeed(500, 950); }
void set_rsx_clock_500_1000()   { SetRsxClockSpeed(500, 1000); }*/

//------------------------------------------------------------------------------
// Core clock: 100 MHz → 1000 MHz in 50 MHz steps
//------------------------------------------------------------------------------
/*void set_rsx_core_clock_100()  { SetRsxCoreClockSpeed(100);  }
void set_rsx_core_clock_150()  { SetRsxCoreClockSpeed(150);  }
void set_rsx_core_clock_200()  { SetRsxCoreClockSpeed(200);  }
void set_rsx_core_clock_250()  { SetRsxCoreClockSpeed(250);  }
void set_rsx_core_clock_300()  { SetRsxCoreClockSpeed(300);  }
void set_rsx_core_clock_350()  { SetRsxCoreClockSpeed(350);  }
void set_rsx_core_clock_400()  { SetRsxCoreClockSpeed(400);  }
void set_rsx_core_clock_450()  { SetRsxCoreClockSpeed(450);  }
void set_rsx_core_clock_500()  { SetRsxCoreClockSpeed(500);  }
void set_rsx_core_clock_550()  { SetRsxCoreClockSpeed(550);  }
void set_rsx_core_clock_600()  { SetRsxCoreClockSpeed(600);  }
void set_rsx_core_clock_650()  { SetRsxCoreClockSpeed(650);  }
void set_rsx_core_clock_700()  { SetRsxCoreClockSpeed(700);  }
void set_rsx_core_clock_750()  { SetRsxCoreClockSpeed(750);  }
void set_rsx_core_clock_800()  { SetRsxCoreClockSpeed(800);  }
void set_rsx_core_clock_850()  { SetRsxCoreClockSpeed(850);  }
void set_rsx_core_clock_900()  { SetRsxCoreClockSpeed(900);  }
void set_rsx_core_clock_950()  { SetRsxCoreClockSpeed(950);  }
void set_rsx_core_clock_1000() { SetRsxCoreClockSpeed(1000); }*/

void set_rsx_core_clock_100()  { apply_rsx_core_clock(100);  }
void set_rsx_core_clock_150()  { apply_rsx_core_clock(150);  }
void set_rsx_core_clock_200()  { apply_rsx_core_clock(200);  }
void set_rsx_core_clock_250()  { apply_rsx_core_clock(250);  }
void set_rsx_core_clock_300()  { apply_rsx_core_clock(300);  }
void set_rsx_core_clock_350()  { apply_rsx_core_clock(350);  }
void set_rsx_core_clock_400()  { apply_rsx_core_clock(400);  }
void set_rsx_core_clock_450()  { apply_rsx_core_clock(450);  }
void set_rsx_core_clock_500()  { apply_rsx_core_clock(500);  }
void set_rsx_core_clock_550()  { apply_rsx_core_clock(550);  }
void set_rsx_core_clock_600()  { apply_rsx_core_clock(600);  }
void set_rsx_core_clock_650()  { apply_rsx_core_clock(650);  }
void set_rsx_core_clock_700()  { apply_rsx_core_clock(700);  }
void set_rsx_core_clock_750()  { apply_rsx_core_clock(750);  }
void set_rsx_core_clock_800()  { apply_rsx_core_clock(800);  }
void set_rsx_core_clock_850()  { apply_rsx_core_clock(850);  }
void set_rsx_core_clock_900()  { apply_rsx_core_clock(900);  }
void set_rsx_core_clock_950()  { apply_rsx_core_clock(950);  }
void set_rsx_core_clock_1000() { apply_rsx_core_clock(1000); }

//------------------------------------------------------------------------------
// Memory clock: 100 MHz → 1000 MHz in 25 MHz steps
//------------------------------------------------------------------------------
/*void set_rsx_mem_clock_100()  { SetRsxMemoryClockSpeed(100);  }
void set_rsx_mem_clock_125()  { SetRsxMemoryClockSpeed(125);  }
void set_rsx_mem_clock_150()  { SetRsxMemoryClockSpeed(150);  }
void set_rsx_mem_clock_175()  { SetRsxMemoryClockSpeed(175);  }
void set_rsx_mem_clock_200()  { SetRsxMemoryClockSpeed(200);  }
void set_rsx_mem_clock_225()  { SetRsxMemoryClockSpeed(225);  }
void set_rsx_mem_clock_250()  { SetRsxMemoryClockSpeed(250);  }
void set_rsx_mem_clock_275()  { SetRsxMemoryClockSpeed(275);  }
void set_rsx_mem_clock_300()  { SetRsxMemoryClockSpeed(300);  }
void set_rsx_mem_clock_325()  { SetRsxMemoryClockSpeed(325);  }
void set_rsx_mem_clock_350()  { SetRsxMemoryClockSpeed(350);  }
void set_rsx_mem_clock_375()  { SetRsxMemoryClockSpeed(375);  }
void set_rsx_mem_clock_400()  { SetRsxMemoryClockSpeed(400);  }
void set_rsx_mem_clock_425()  { SetRsxMemoryClockSpeed(425);  }
void set_rsx_mem_clock_450()  { SetRsxMemoryClockSpeed(450);  }
void set_rsx_mem_clock_475()  { SetRsxMemoryClockSpeed(475);  }
void set_rsx_mem_clock_500()  { SetRsxMemoryClockSpeed(500);  }
void set_rsx_mem_clock_525()  { SetRsxMemoryClockSpeed(525);  }
void set_rsx_mem_clock_550()  { SetRsxMemoryClockSpeed(550);  }
void set_rsx_mem_clock_575()  { SetRsxMemoryClockSpeed(575);  }
void set_rsx_mem_clock_600()  { SetRsxMemoryClockSpeed(600);  }
void set_rsx_mem_clock_625()  { SetRsxMemoryClockSpeed(625);  }
void set_rsx_mem_clock_650()  { SetRsxMemoryClockSpeed(650);  }
void set_rsx_mem_clock_675()  { SetRsxMemoryClockSpeed(675);  }
void set_rsx_mem_clock_700()  { SetRsxMemoryClockSpeed(700);  }
void set_rsx_mem_clock_725()  { SetRsxMemoryClockSpeed(725);  }
void set_rsx_mem_clock_750()  { SetRsxMemoryClockSpeed(750);  }
void set_rsx_mem_clock_775()  { SetRsxMemoryClockSpeed(775);  }
void set_rsx_mem_clock_800()  { SetRsxMemoryClockSpeed(800);  }
void set_rsx_mem_clock_825()  { SetRsxMemoryClockSpeed(825);  }
void set_rsx_mem_clock_850()  { SetRsxMemoryClockSpeed(850);  }
void set_rsx_mem_clock_875()  { SetRsxMemoryClockSpeed(875);  }
void set_rsx_mem_clock_900()  { SetRsxMemoryClockSpeed(900);  }
void set_rsx_mem_clock_925()  { SetRsxMemoryClockSpeed(925);  }
void set_rsx_mem_clock_950()  { SetRsxMemoryClockSpeed(950);  }
void set_rsx_mem_clock_975()  { SetRsxMemoryClockSpeed(975);  }
void set_rsx_mem_clock_1000() { SetRsxMemoryClockSpeed(1000); }*/

void set_rsx_mem_clock_100()  { apply_rsx_mem_clock(100);  }
void set_rsx_mem_clock_125()  { apply_rsx_mem_clock(125);  }
void set_rsx_mem_clock_150()  { apply_rsx_mem_clock(150);  }
void set_rsx_mem_clock_175()  { apply_rsx_mem_clock(175);  }
void set_rsx_mem_clock_200()  { apply_rsx_mem_clock(200);  }
void set_rsx_mem_clock_225()  { apply_rsx_mem_clock(225);  }
void set_rsx_mem_clock_250()  { apply_rsx_mem_clock(250);  }
void set_rsx_mem_clock_275()  { apply_rsx_mem_clock(275);  }
void set_rsx_mem_clock_300()  { apply_rsx_mem_clock(300);  }
void set_rsx_mem_clock_325()  { apply_rsx_mem_clock(325);  }
void set_rsx_mem_clock_350()  { apply_rsx_mem_clock(350);  }
void set_rsx_mem_clock_375()  { apply_rsx_mem_clock(375);  }
void set_rsx_mem_clock_400()  { apply_rsx_mem_clock(400);  }
void set_rsx_mem_clock_425()  { apply_rsx_mem_clock(425);  }
void set_rsx_mem_clock_450()  { apply_rsx_mem_clock(450);  }
void set_rsx_mem_clock_475()  { apply_rsx_mem_clock(475);  }
void set_rsx_mem_clock_500()  { apply_rsx_mem_clock(500);  }
void set_rsx_mem_clock_525()  { apply_rsx_mem_clock(525);  }
void set_rsx_mem_clock_550()  { apply_rsx_mem_clock(550);  }
void set_rsx_mem_clock_575()  { apply_rsx_mem_clock(575);  }
void set_rsx_mem_clock_600()  { apply_rsx_mem_clock(600);  }
void set_rsx_mem_clock_625()  { apply_rsx_mem_clock(625);  }
void set_rsx_mem_clock_650()  { apply_rsx_mem_clock(650);  }
void set_rsx_mem_clock_675()  { apply_rsx_mem_clock(675);  }
void set_rsx_mem_clock_700()  { apply_rsx_mem_clock(700);  }
void set_rsx_mem_clock_725()  { apply_rsx_mem_clock(725);  }
void set_rsx_mem_clock_750()  { apply_rsx_mem_clock(750);  }
void set_rsx_mem_clock_775()  { apply_rsx_mem_clock(775);  }
void set_rsx_mem_clock_800()  { apply_rsx_mem_clock(800);  }
void set_rsx_mem_clock_825()  { apply_rsx_mem_clock(825);  }
void set_rsx_mem_clock_850()  { apply_rsx_mem_clock(850);  }
void set_rsx_mem_clock_875()  { apply_rsx_mem_clock(875);  }
void set_rsx_mem_clock_900()  { apply_rsx_mem_clock(900);  }
void set_rsx_mem_clock_925()  { apply_rsx_mem_clock(925);  }
void set_rsx_mem_clock_950()  { apply_rsx_mem_clock(950);  }
void set_rsx_mem_clock_975()  { apply_rsx_mem_clock(975);  }
void set_rsx_mem_clock_1000() { apply_rsx_mem_clock(1000); }
