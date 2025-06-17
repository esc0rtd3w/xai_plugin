#ifndef __HEN_H__
#define __HEN_H__

#include <stdint.h>
#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/timer.h>
#include "log.h"

// Legacy HEN
uint64_t peekq(uint64_t addr);
uint32_t peekq32(uint64_t addr);
void pokeq( uint64_t addr, uint64_t val);
void pokeq32(uint64_t address, uint32_t value);

#define process_id_t uint32_t
extern process_id_t vsh_pid;

#define SYSCALL8_OPCODE_PS3MAPI			 		0x7777
#define PS3MAPI_OPCODE_GET_ALL_PROC_PID			0x0021
#define PS3MAPI_OPCODE_GET_PROC_NAME_BY_PID		0x0022
#define PS3MAPI_OPCODE_GET_PROC_MEM				0x0031
#define PS3MAPI_OPCODE_SET_PROC_MEM				0x0032
#define MAX_PROCESS 16

void kpatch(uint64_t kaddr, uint64_t kbytes);
int read_vsh(uint64_t address, char *buf, int size);
int poke_vsh(uint64_t address, char *buf, int size);

void reset_psn_patches();
void psn_patch(uint32_t paddr, uint32_t pbytes, bool reset);

void check_temperature();
void dump_idps();
void dump_psid();
int dump_lv2();

void log_to_usb(const char *message);

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

void write_toggle(char* path_to_file, char* message);
void toggle_generic(char* path_to_file, char* name, int reverse_toggle);
void read_write_generic(const char* src, const char* dest);
void read_write_generic_notify(const char* src, const char* dest);
void read_write_generic2(const char* src, const char* dest, CellFsMode chmod);
void remove_directory(char*src);
void remove_directory_bug(char*_src);
void remove_file(char* path_to_file, char* message);

#endif __HEN_H__