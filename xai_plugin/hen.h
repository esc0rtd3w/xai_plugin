#ifndef __HEN_H__
#define __HEN_H__

#include <stdint.h>
#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/timer.h>

#define process_id_t uint32_t
extern process_id_t vsh_pid;

#define SYSCALL8_OPCODE_PS3MAPI			 		0x7777
#define PS3MAPI_OPCODE_GET_ALL_PROC_PID			0x0021
#define PS3MAPI_OPCODE_GET_PROC_NAME_BY_PID		0x0022
#define PS3MAPI_OPCODE_GET_PROC_MEM				0x0031
#define PS3MAPI_OPCODE_SET_PROC_MEM				0x0032
#define MAX_PROCESS 16

// Legacy HEN
uint64_t peekq(uint64_t addr);
uint32_t peekq32(uint64_t addr);
void pokeq( uint64_t addr, uint64_t val);
void pokeq32(uint64_t address, uint32_t value);

//static inline uint64_t lv1_read2(uint64_t addr);
//static inline void lv1_write2(uint64_t addr, uint64_t value);

void kpatch(uint64_t kaddr, uint64_t kbytes);
int read_vsh(uint64_t address, char *buf, int size);
int poke_vsh(uint64_t address, char *buf, int size);

void reset_psn_patches();
void psn_patch(uint32_t paddr, uint32_t pbytes, bool reset);

void check_temperature();
void dump_idps();
void dump_psid();
int dump_lv1();
int dump_lv2();

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



// RSX Overclocking
/*#define eieio()                \
	{                          \
		asm volatile("eieio"); \
		asm volatile("sync");  \
	}*/

void log_to_usb(const char *message);

int dump_lv2();
void toggle_auto_update();
void toggle_hen_repair();
void toggle_patch_libaudio();
void toggle_hotkey_polling();
void toggle_app_home();
void toggle_quick_preview();
void toggle_hen_dev_build(); 
void uninstall_hen();
int switch_hen_mode(int mode);// Used for switching from release to debug
void disable_remaps_on_next_boot();
void toggle_rap_bin();

// Clear Web Cache Functions (History, Auth Cache, Cookie)
void toggle_clear_web_history();
void toggle_clear_web_auth_cache();
void toggle_clear_web_cookie();

// Clear PSN Cache Functions (CI, MI, PTL)
void toggle_clear_psn_ci();
void toggle_clear_psn_mi();
void toggle_clear_psn_ptl();

// BadHTAB Testing
int dump_full_ram();
int dump_lv1();
bool test_lv1_peek();
bool test_lv1_peek32();
bool test_lv1_poke();
bool test_lv1_poke32();
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
void lv1_read(uint64_t addr, uint64_t size, void *out_Buf);
void lv1_write(uint64_t addr, uint64_t size, const void *in_Buf);

void write_toggle(char* path_to_file, char* message);
void toggle_generic(char* path_to_file, char* name, int reverse_toggle);
void read_write_generic(const char* src, const char* dest);
void read_write_generic_notify(const char* src, const char* dest);
void read_write_generic2(const char* src, const char* dest, CellFsMode chmod);
void remove_directory(char*src);
void remove_directory_bug(char*_src);
void remove_file(char* path_to_file, char* message);

#endif __HEN_H__