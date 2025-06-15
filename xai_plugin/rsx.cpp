#include "rsx.h"
#include "hfw_settings.h"
#include "hen.h"
#include "badwdsd.h"
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

