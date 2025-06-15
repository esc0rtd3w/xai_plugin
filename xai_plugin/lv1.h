#ifndef __LV1_H__
#define __LV1_H__

#include "hen.h"

int dump_full_ram();
int dump_lv1();
bool test_lv1_peek();
bool test_lv1_peek32();
bool test_lv1_poke();
bool test_lv1_poke32();

// LV1 Patches
bool lv1_patch_pattern(uint64_t addr, uint64_t expected, uint64_t patch, uint64_t mask);
int toggle_lv1_patch(const char* name, uint64_t addr, uint64_t ovalue, uint64_t pvalue);
int toggle_lv1_patch32(const char* name, uint64_t addr, uint32_t ovalue, uint32_t pvalue);
int unmask_bootldr();

void toggle_lv1_patch_unmask_bootldr();
void toggle_lv1_patch_test1();
void toggle_lv1_patch_test2();

union clock_s {
public:
    struct {
    public:
        uint8_t junk1;
        uint8_t junk2;
        uint8_t mul;
        uint8_t junk3;
    };
    uint32_t value;
};

// HV dump region functions
int dump_lv0_code();
int dump_lv1_code();
int dump_lv2_region();
//int dump_spe_mmio(int idx);
int dump_spe0_mmio();
int dump_spe1_mmio();
int dump_spe2_mmio();
int dump_spe3_mmio();
int dump_spe4_mmio();
int dump_spe5_mmio();
int dump_spe6_mmio();
int dump_pervasive_mem();
//int dump_spe_shadow(int idx);
int dump_spe1_shadow();
int dump_spe2_shadow();
int dump_spe3_shadow();
int dump_spe4_shadow();
int dump_spe5_shadow();
int dump_spe6_shadow();
int dump_xdr_ch1_size();
int dump_xdr_ch0_size();
int dump_xdr_type();

int dump_sb_bus_base();
int dump_sata1_regs();
int dump_sata2_regs();
int dump_usb1_regs();
int dump_usb2_regs();
int dump_gelic_regs();
int dump_encdec_regs();
int dump_sb_ext_intc();
int dump_sb_int_hdl1();
int dump_sb_int_hdl2();
int dump_sb_status();

int dump_syscon_pkt_hdr();
int dump_syscon_pkt_bdy();
int dump_syscon_recv1();
int dump_syscon_recv2();
int dump_syscon_send_hdr();
int dump_syscon_send_bdy();
int dump_syscon_send1();
int dump_syscon_send2();
int dump_syscon_rcv3();
int dump_syscon_testbit();
int dump_syscon_notify();

int dump_sata1_bar();
int dump_sata2_bar();
int dump_gelic_bar();
int dump_encdec_bar();
int dump_encdec_test();
int dump_encdec_cmd();
int dump_usb1_bar();
int dump_usb2_bar();

int dump_sata1_bar2();
int dump_sata2_bar2();
int dump_sata1_bar3();
int dump_sata2_bar3();
int dump_usb1_bar2();
int dump_usb2_bar2();

int dump_nor_flash();
int dump_sys_rom();

int dump_avmngr_regs1();
int dump_avmngr_regs2();
int dump_av_outctrl();
int dump_av_pllctrl();
int dump_av_misc1();
int dump_av_misc2();
int dump_av_misc3();
int dump_av_misc4();
int dump_av_misc5();

int dump_gpu_mem1();
int dump_gpu_mem2();
int dump_gpu_mem3();
int dump_gpu_mem4();
int dump_gpu_mem5();

int dump_rsx_intstate();
int dump_ramin_all();
int dump_ramin_hash();
int dump_ramin_fifo();
int dump_dma_objs();
int dump_graph_objs();
int dump_graph_ctx();

int dump_gameos0();
int dump_gameos1();
int dump_gameos2();
int dump_gameos_htab();

// Dump all regions at once
int dump_all_regions();


#endif __LV1_H__