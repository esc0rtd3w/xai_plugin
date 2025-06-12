#ifndef __HEN_H__
#define __HEN_H__

#define process_id_t uint32_t
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

void kpatch(uint64_t kaddr, uint64_t kbytes);
int read_vsh(uint64_t address, char *buf, int size);
int poke_vsh(uint64_t address, char *buf, int size);

void reset_psn_patches();
void psn_patch(uint32_t paddr, uint32_t pbytes, bool reset);

void write_toggle(char* path_to_file, char* message);
void toggle_generic(char* path_to_file, char* name, int reverse_toggle);
void read_write_generic(const char* src, const char* dest);
void read_write_generic_notify(const char* src, const char* dest);
void read_write_generic2(const char* src, const char* dest, CellFsMode chmod);
void remove_directory(char*src);
void remove_directory_bug(char*_src);

#endif __HEN_H__