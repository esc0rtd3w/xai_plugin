#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/ppu_thread.h>
#include <sys/prx.h>
#include "xmb_plugin.h"
#include "log.h"
#include "hfw_settings.h"
#include "cobra.h"
#include "gccpch.h"
#include "functions.h"
#include "rebug.h"
#include "qa.h"
#include "savegames.h"
#include "cex2dex.h"
#include "eeprom.h"
#include "rebugtoolbox.h"
#include "erk.h"

// PS3HEN
#include "hen.h"
#include "badwdsd.h"
#include "rsx.h"
#include "lv1.h"

#define XAI_VERSION "XAI Version 1.20"

SYS_MODULE_INFO(xai_plugin, 0, 1, 1);
SYS_MODULE_START(_xai_plugin_prx_entry);
SYS_MODULE_STOP(_xai_plugin_prx_stop);
SYS_MODULE_EXIT(_xai_plugin_prx_exit);

SYS_LIB_DECLARE_WITH_STUB(LIBNAME, SYS_LIB_AUTO_EXPORT, STUBNAME);
SYS_LIB_EXPORT(_xai_plugin_export_function, LIBNAME);

xmb_plugin_xmm0 * xmm0_interface;
xmb_plugin_xmb2 * xmb2_interface;
xmb_plugin_mod0 * mod0_interface;

sys_ppu_thread_t thread_id = 0;
const char * action_thread;

int LoadPlugin(char *pluginname, void *handler)
{
	log_function("xai_plugin", "1", __FUNCTION__, "(%s)\n", pluginname);
	return xmm0_interface->LoadPlugin3(xmm0_interface->GetPluginIdByName(pluginname), handler, 0); 
}

int GetPluginInterface(const char *pluginname, int interface_)
{
	return plugin_GetInterface(FindPlugin(pluginname), interface_);
}

void * getNIDfunc(const char * vsh_module, uint32_t fnid)
{	
	// 0x10000 = ELF
	// 0x10080 = segment 2 start
	// 0x10200 = code start	

	uint32_t table = (*(uint32_t*)0x1008C) + 0x984; // vsh table address
	
	while(((uint32_t)*(uint32_t*)table) != 0)
	{
		uint32_t* export_stru_ptr = (uint32_t*)*(uint32_t*)table; // ptr to export stub, size 2C, "sys_io" usually... Exports:0000000000635BC0 stru_635BC0:    ExportStub_s <0x1C00, 1, 9, 0x39, 0, 0x2000000, aSys_io, ExportFNIDTable_sys_io, ExportStubTable_sys_io>
			
		const char* lib_name_ptr =  (const char*)*(uint32_t*)((char*)export_stru_ptr + 0x10);
				
		if(strncmp(vsh_module, lib_name_ptr, strlen(lib_name_ptr)) == 0)
		{
			// we got the proper export struct
			uint32_t lib_fnid_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x14);
			uint32_t lib_func_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x18);
			uint16_t count = *(uint16_t*)((char*)export_stru_ptr + 6); // amount of exports

			for(int i = 0; i < count; i++)
			{
				if(fnid == *(uint32_t*)((char*)lib_fnid_ptr + i * 4))								
					return (void*&)*((uint32_t*)(lib_func_ptr) + i); // take adress from OPD				
			}
		}

		table = table + 4;
	}

	return 0;
}

int load_functions()
{	
	setNIDfunc(FindPlugin, "paf", 0xF21655F3);
	setNIDfunc(plugin_GetInterface, "paf", 0x23AFB290);
	setNIDfunc(plugin_SetInterface, "paf", 0xA1DC401);
	setNIDfunc(plugin_SetInterface2, "paf", 0x3F7CB0BF);

	load_log_functions();
	load_cfw_functions();
	load_saves_functions();
	
	xmm0_interface = (xmb_plugin_xmm0 *)GetPluginInterface("xmb_plugin", 'XMM0');
	xmb2_interface = (xmb_plugin_xmb2 *)GetPluginInterface("xmb_plugin", 'XMB2');
	
	setlogpath("/dev_hdd0/tmp/hfw_settings.log"); // Default path

	uint8_t data;
	int ret = read_product_mode_flag(&data);

	if(ret == CELL_OK)
	{
		if(data != 0xFF)		
			setlogpath("/dev_usb/hfw_settings.log"); // To get output data		
	}

	return 0;
}

// An exported function is needed to generate the project's PRX stub export library
extern "C" int _xai_plugin_export_function(void)
{
    return CELL_OK;
}

extern "C" int _xai_plugin_prx_entry(size_t args, void *argp)
{	
	load_functions();
	log_function("xai_plugin", "", __FUNCTION__, "()\n", 0);
	plugin_SetInterface2(*(unsigned int*)argp, 1, xai_plugin_functions);

    return SYS_PRX_RESIDENT;
}

extern "C" int _xai_plugin_prx_stop(void)
{
	log_function("xai_plugin", "", __FUNCTION__, "()\n", 0);
    return SYS_PRX_STOP_OK;
}

extern "C" int _xai_plugin_prx_exit(void)
{
	log_function("xai_plugin", "", __FUNCTION__, "()\n", 0);
    return SYS_PRX_STOP_OK;
}

void xai_plugin_interface::xai_plugin_init(int view)
{
	log_function("xai_plugin", "1", __FUNCTION__, "()\n", 0);
	plugin_SetInterface(view, 'ACT0', xai_plugin_action_if);
}

int xai_plugin_interface::xai_plugin_start(void * view)
{
	log_function("xai_plugin", "1", __FUNCTION__, "()\n", 0);
	return SYS_PRX_START_OK; 
}

int xai_plugin_interface::xai_plugin_stop(void)
{
	log_function("xai_plugin", "1", __FUNCTION__, "()\n", 0);
	return SYS_PRX_STOP_OK;
}

void xai_plugin_interface::xai_plugin_exit(void)
{
	log_function("xai_plugin", "1", __FUNCTION__, "()\n", 0);
}

static void plugin_thread(uint64_t arg)
{

	// HFW Tools XML

	// Restart PS3
	if(strcmp(action_thread,"soft_reboot_action")==0)
	{
		rebootXMB(SYS_SOFT_REBOOT);
	}
	else if(strcmp(action_thread,"hard_reboot_action")==0)
	{
		rebootXMB(SYS_HARD_REBOOT);
	}
	else if(strcmp(action_thread,"power_off_action")==0)
	{
		rebootXMB(SYS_SHUTDOWN);
	}
	
	// In-Game Settings
	else if (strcmp(action_thread, "override_sfo") == 0)
	{
		override_sfo();
	}
	//else if (strcmp(action_thread, "enable_screenshot") == 0)
	//{
	//	enable_screenshot();
	//}
	//else if(strcmp(action_thread,"enable_recording")==0)
	//{
	//enable_recording();
	//}

	// Basic Tools
	else if(strcmp(action_thread, "show_temp") == 0)	
	{
		check_temperature();
	}

	// QA Tools
	else if(strcmp(action_thread, "check_qa") == 0)
	{
		read_qa_flag();
	}

	// Dump Tools
	else if(strcmp(action_thread,"clean_log")==0)
	{		
		clean_log();
	}
	else if (strcmp(action_thread, "dump_idps") == 0)
	{
		dump_idps();
	}
	else if (strcmp(action_thread, "dump_psid") == 0)
	{
		dump_psid();
	}
	else if (strcmp(action_thread, "dump_ids") == 0) {
		dump_ids();
	}
	else if(strcmp(action_thread,"log_klic")==0)
	{
		log_klic();
	}
	else if(strcmp(action_thread,"log_secureid")==0)
	{
		log_secureid();
	}
	else if (strcmp(action_thread, "dump_disc_key") == 0)
	{
		dump_disc_key();
	}
	else if (strcmp(action_thread, "backup_registry") == 0)
	{
		backup_registry();
	}

	// Service Tools
	else if (strcmp(action_thread, "applicable_version") == 0)
	{
		applicable_version();
	}
	else if (strcmp(action_thread, "fs_check") == 0)
	{
		//if(fs_check() == CELL_OK)
		//	xmb_reboot(SYS_SOFT_REBOOT);
		sys_sm_shutdown(SYS_SOFT_REBOOT); // no need to unlink files.
	}
	else if (strcmp(action_thread, "rebuild_db") == 0)
	{
		rebuild_db();
		rebootXMB(SYS_SOFT_REBOOT);
	}
	else if (strcmp(action_thread, "recovery_mode") == 0)
	{
		recovery_mode();
		rebootXMB(SYS_HARD_REBOOT);
	}
	else if(strcmp(action_thread, "toggle_hdd_space") == 0)
	{
		unlock_hdd_space();
	}
	//else if(strcmp(action_thread,"service_mode")==0)
	//{
	//	if(service_mode() == true)
	//		rebootXMB(SYS_HARD_REBOOT);
	//}

	// Update Tools

	// PS3HEN Automatic Update Toggle
	else if (strcmp(action_thread, "toggle_auto_update") == 0)
	{
		toggle_auto_update();
	}

	// PS3HEN libaudio Patch Toggle
	else if (strcmp(action_thread, "toggle_patch_libaudio") == 0)
	{
		toggle_patch_libaudio();
	}

	// Clear Web Cache: History
	else if (strcmp(action_thread, "toggle_clear_web_history") == 0)
	{
		toggle_clear_web_history();
	}

	// Clear Web Cache: Auth Cache
	else if (strcmp(action_thread, "toggle_clear_web_auth_cache") == 0)
	{
		toggle_clear_web_auth_cache();
	}

	// Clear Web Cache: Cookie
	else if (strcmp(action_thread, "toggle_clear_web_cookie") == 0)
	{
		toggle_clear_web_cookie();
	}

	// Clear PSN Cache: CI
	else if (strcmp(action_thread, "toggle_clear_psn_ci") == 0)
	{
		toggle_clear_psn_ci();
	}

	// Clear PSN Cache: MI
	else if (strcmp(action_thread, "toggle_clear_psn_mi") == 0)
	{
		toggle_clear_psn_mi();
	}

	// Clear PSN Cache: PTL
	else if (strcmp(action_thread, "toggle_clear_psn_ptl") == 0)
	{
		toggle_clear_psn_ptl();
	}

	// Switch HEN Mode Release
	else if (strcmp(action_thread, "hen_mode_release") == 0)
	{
		switch_hen_mode(0);
	}

	// Switch HEN Mode Debug
	else if (strcmp(action_thread, "hen_mode_debug") == 0)
	{
		switch_hen_mode(1);
	}

	// Switch HEN Mode USB Release
	else if (strcmp(action_thread, "hen_mode_usb_000") == 0)
	{
		switch_hen_mode(2);
	}

	// Switch HEN Mode USB Debug
	else if (strcmp(action_thread, "hen_mode_usb_001") == 0)
	{
		switch_hen_mode(3);
	}

	// PS3HEN Repair Installation Files Toggle
	//else if (strcmp(action_thread, "toggle_hen_repair") == 0)
	//{
	//	toggle_hen_repair();
	//}

	// Toggle Developer Build Type
	else if (strcmp(action_thread, "toggle_hen_dev_build") == 0)
	{
		toggle_hen_dev_build();
	}

	// Disable Remapping On Next Reboot
	else if (strcmp(action_thread, "disable_remaps_on_next_boot") == 0)
	{
		disable_remaps_on_next_boot();
	}

	// Remove check file for HEN Install Flag
	else if (strcmp(action_thread, "trigger_hen_install") == 0)
	{
		remove_file("/dev_rewrite/vsh/resource/explore/icon/hen_enable.png", "Reboot to re-install PS3HEN");
	}

	// Uninstall PS3HEN
	else if (strcmp(action_thread, "uninstall_hen") == 0)
	{
		uninstall_hen();
	}

	// Toggle HotKey Polling on HEN Launch
	else if (strcmp(action_thread, "toggle_hotkey_polling") == 0)
	{
		toggle_hotkey_polling();
	}

	// Toggle app_home support
	else if (strcmp(action_thread, "toggle_app_home") == 0)
	{
		toggle_app_home();
	}

	// Toggle Quick Preview support
	else if (strcmp(action_thread, "toggle_quick_preview") == 0)
	{
		toggle_quick_preview();
	}

	// Toggle rap.bin support
	else if (strcmp(action_thread, "toggle_rap_bin") == 0)
	{
		toggle_rap_bin();
	}

	// BadHTAB Testing
	else if (strcmp(action_thread, "dump_erk") == 0) {
		dumpERK(ERK);
	}
	else if (strcmp(action_thread, "dump_metldr") == 0) {
		dumpERK(METLDR);
	}
	else if (strcmp(action_thread, "dump_lv2") == 0) {
		dump_lv(LV2);
	}
	else if (strcmp(action_thread, "dump_lv1") == 0) {
		dump_lv(LV1);
	}
	else if (strcmp(action_thread, "dump_ram") == 0) {
		dump_lv(RAM);
	}
	else if (strcmp(action_thread, "dump_sysrom") == 0) {
		dump_sysrom();
	}
	else if (strcmp(action_thread, "dump_eeprom") == 0) {
		dump_eeprom();
	}
	else if (strcmp(action_thread, "get_token_seed") == 0) {
		get_token_seed();
	}
	else if (strcmp(action_thread, "dump_flash") == 0) {
		dumpFlash();
	}
	else if (strcmp(action_thread, "dump_syscon_log") == 0) {
		sm_error_log();
	}
	else if(strcmp(action_thread, "dump_full_ram") == 0)	
	{
		dump_full_ram();		
	}
	else if(strcmp(action_thread, "badhtab_copy_log") == 0)	
	{
		badhtab_copy_log();		
	}
	else if(strcmp(action_thread, "badhtab_toggle_glitcher_test") == 0)	
	{
		badhtab_toggle_glitcher_test();		
	}
	else if(strcmp(action_thread, "badhtab_toggle_skip_stage1") == 0)	
	{
		badhtab_toggle_skip_stage1();		
	}
	//else if(strcmp(action_thread, "badhtab_toggle_skip_stage_cfw") == 0)	
	//{
	//	badhtab_toggle_skip_stage_cfw();		
	//}
	else if(strcmp(action_thread, "badhtab_toggle_skip_stage2") == 0)	
	{
		badhtab_toggle_skip_stage2();		
	}
	else if(strcmp(action_thread, "badhtab_toggle_skip_patch_more_lv1") == 0)	
	{
		badhtab_toggle_skip_patch_more_lv1();		
	}
	else if(strcmp(action_thread, "badhtab_toggle_lv1_dump") == 0)	
	{
		badhtab_toggle_lv1_dump();		
	}
	else if(strcmp(action_thread, "badhtab_toggle_lv1_dump_240m") == 0)	
	{
		badhtab_toggle_lv1_dump_240m();		
	}
	else if(strcmp(action_thread, "badhtab_toggle_otheros") == 0)	
	{
		badhtab_toggle_otheros();		
	}
	else if(strcmp(action_thread, "badhtab_toggle_lv2_kernel_self") == 0)	
	{
		badhtab_toggle_lv2_kernel_self();		
	}
	else if(strcmp(action_thread, "badhtab_toggle_lv2_kernel_fself") == 0)	
	{
		badhtab_toggle_lv2_kernel_fself();		
	}
	else if(strcmp(action_thread, "test_lv1_peek") == 0)
	{
		test_lv1_peek();
	}
	else if(strcmp(action_thread, "test_lv1_peek32") == 0)
	{
		test_lv1_peek32();
	}
	else if(strcmp(action_thread, "test_lv1_poke") == 0)
	{
		test_lv1_poke();
	}
	else if(strcmp(action_thread, "test_lv1_poke32") == 0)
	{
		test_lv1_poke32();
	}

	// BadWDSD/qCFW
	else if(strcmp(action_thread, "badwdsd_install_qcfw") == 0)	
	{
		InstallQCFW(false, false, false);// Default FALSE (doLegacy, doSkipRosCompare, doFlashRos1)
	}
	else if(strcmp(action_thread, "badwdsd_install_stagex_only") == 0)	
	{
		InstallStagexOnly();
	}
	else if(strcmp(action_thread, "badwdsd_install_coreos_only") == 0)	
	{
		InstallCoreOSOnly(false, false);// Default FALSE doSkipRosCompare, doFlashRos1)
	}

	else if (strcmp(action_thread, "badwdsd_install_qcfw") == 0)
	{
		if (!InstallQCFW(false, false, false))
		{
			showMessageRaw("QCFW install failed, exiting.\n", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return;
		}
	}
	else if (strcmp(action_thread, "badwdsd_install_stagex_only") == 0)
	{
		if (!InstallStagexOnly())
		{
			showMessageRaw("Stagex install failed, exiting.\n", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return;
		}
	}
	else if (strcmp(action_thread, "badwdsd_install_coreos_only") == 0)
	{
		if (!InstallCoreOSOnly(false, false))
		{
			showMessageRaw("CoreOS install failed, exiting.\n", (char*)XAI_PLUGIN, (char*)TEX_ERROR);
			return;
		}
	}
	
	else if(strcmp(action_thread, "badwdsd_verify_qcfw") == 0)	
	{
		VerifyQCFW();
	}
	else if(strcmp(action_thread, "badwdsd_verify_stagex_only") == 0)	
	{
		VerifyStagexOnly();
	}
	else if(strcmp(action_thread, "badwdsd_verify_coreos_only") == 0)	
	{
		VerifyCoreOSOnly();
	}
	
	// Test indivdual functions
	else if(strcmp(action_thread, "badwdsd_get_fw_version") == 0)	
	{
		GetFWVersion();
	}
	else if(strcmp(action_thread, "badwdsd_check_fw_version") == 0)	
	{
		CheckFWVersion();
	}
	else if(strcmp(action_thread, "badwdsd_get_target") == 0)	
	{
		GetTarget();
	}
	else if(strcmp(action_thread, "badwdsd_get_flash_type") == 0)	
	{
		GetFlashType();
	}
	else if(strcmp(action_thread, "badwdsd_is_exploited") == 0)	
	{
		IsExploited();
	}
	else if(strcmp(action_thread, "badwdsd_patch_update_manager") == 0)	
	{
		patch_um();
	}
	else if(strcmp(action_thread, "badwdsd_patch_update_manager_eeprom_rw") == 0)	
	{
		patch_um_eeprom();
	}
	else if(strcmp(action_thread, "badwdsd_get_bank_indicator") == 0)	
	{
		get_bank_indicator();
	}
	else if(strcmp(action_thread, "badwdsd_set_bank_indicator_00") == 0)	
	{
		set_bank_indicator(0x00);
	}
	else if(strcmp(action_thread, "badwdsd_set_bank_indicator_ff") == 0)	
	{
		set_bank_indicator(0xff);
	}
	else if(strcmp(action_thread, "badwdsd_nor_read_compare_ros_banks") == 0)	
	{
		CompareROSBanks();
	}

	// LV1 Patches
	else if (strcmp(action_thread, "enable_hvdbg") == 0)
	{
		enable_hvdbg();
	}
	else if (strcmp(action_thread, "toggle_lv1_patch_unmask_bootldr") == 0)
	{
		toggle_lv1_patch_unmask_bootldr();
	}
	else if (strcmp(action_thread, "toggle_lv1_patch_test1") == 0)
	{
		toggle_lv1_patch_test1();
	}
	else if (strcmp(action_thread, "toggle_lv1_patch_test2") == 0)
	{
		toggle_lv1_patch_test2();
	}



	// Hypervisor dump actions
	else if (strcmp(action_thread, "dump_lv0_code") == 0) {
		dump_lv0_code();
	}
	else if (strcmp(action_thread, "dump_lv1_code") == 0) {
		dump_lv1_code();
	}
	else if (strcmp(action_thread, "dump_lv2_region") == 0) {
		dump_lv2_region();
	}
	else if (strcmp(action_thread, "dump_spe0_mmio") == 0) {
		dump_spe0_mmio();
	}
	else if (strcmp(action_thread, "dump_spe1_mmio") == 0) {
		dump_spe1_mmio();
	}
	else if (strcmp(action_thread, "dump_spe2_mmio") == 0) {
		dump_spe2_mmio();
	}
	else if (strcmp(action_thread, "dump_spe3_mmio") == 0) {
		dump_spe3_mmio();
	}
	else if (strcmp(action_thread, "dump_spe4_mmio") == 0) {
		dump_spe4_mmio();
	}
	else if (strcmp(action_thread, "dump_spe5_mmio") == 0) {
		dump_spe5_mmio();
	}
	else if (strcmp(action_thread, "dump_spe6_mmio") == 0) {
		dump_spe6_mmio();
	}
	else if (strcmp(action_thread, "dump_pervasive_mem") == 0) {
		dump_pervasive_mem();
	}
	else if (strcmp(action_thread, "dump_spe1_shadow") == 0) {
		dump_spe1_shadow();
	}
	else if (strcmp(action_thread, "dump_spe2_shadow") == 0) {
		dump_spe2_shadow();
	}
	else if (strcmp(action_thread, "dump_spe3_shadow") == 0) {
		dump_spe3_shadow();
	}
	else if (strcmp(action_thread, "dump_spe4_shadow") == 0) {
		dump_spe4_shadow();
	}
	else if (strcmp(action_thread, "dump_spe5_shadow") == 0) {
		dump_spe5_shadow();
	}
	else if (strcmp(action_thread, "dump_spe6_shadow") == 0) {
		dump_spe6_shadow();
	}
	else if (strcmp(action_thread, "dump_xdr_ch1_size") == 0) {
		dump_xdr_ch1_size();
	}
	else if (strcmp(action_thread, "dump_xdr_ch0_size") == 0) {
		dump_xdr_ch0_size();
	}
	else if (strcmp(action_thread, "dump_xdr_type") == 0) {
		dump_xdr_type();
	}
	else if (strcmp(action_thread, "dump_sb_bus_base") == 0) {
		dump_sb_bus_base();
	}
	else if (strcmp(action_thread, "dump_sata1_regs") == 0) {
		dump_sata1_regs();
	}
	else if (strcmp(action_thread, "dump_sata2_regs") == 0) {
		dump_sata2_regs();
	}
	else if (strcmp(action_thread, "dump_usb1_regs") == 0) {
		dump_usb1_regs();
	}
	else if (strcmp(action_thread, "dump_usb2_regs") == 0) {
		dump_usb2_regs();
	}
	else if (strcmp(action_thread, "dump_gelic_regs") == 0) {
		dump_gelic_regs();
	}
	else if (strcmp(action_thread, "dump_encdec_regs") == 0) {
		dump_encdec_regs();
	}
	else if (strcmp(action_thread, "dump_sb_ext_intc") == 0) {
		dump_sb_ext_intc();
	}
	else if (strcmp(action_thread, "dump_sb_int_hdl1") == 0) {
		dump_sb_int_hdl1();
	}
	else if (strcmp(action_thread, "dump_sb_int_hdl2") == 0) {
		dump_sb_int_hdl2();
	}
	else if (strcmp(action_thread, "dump_sb_status") == 0) {
		dump_sb_status();
	}
	else if (strcmp(action_thread, "dump_syscon_pkt_hdr") == 0) {
		dump_syscon_pkt_hdr();
	}
	else if (strcmp(action_thread, "dump_syscon_pkt_bdy") == 0) {
		dump_syscon_pkt_bdy();
	}
	else if (strcmp(action_thread, "dump_syscon_recv1") == 0) {
		dump_syscon_recv1();
	}
	else if (strcmp(action_thread, "dump_syscon_recv2") == 0) {
		dump_syscon_recv2();
	}
	else if (strcmp(action_thread, "dump_syscon_send_hdr") == 0) {
		dump_syscon_send_hdr();
	}
	else if (strcmp(action_thread, "dump_syscon_send_bdy") == 0) {
		dump_syscon_send_bdy();
	}
	else if (strcmp(action_thread, "dump_syscon_send1") == 0) {
		dump_syscon_send1();
	}
	else if (strcmp(action_thread, "dump_syscon_send2") == 0) {
		dump_syscon_send2();
	}
	else if (strcmp(action_thread, "dump_syscon_rcv3") == 0) {
		dump_syscon_rcv3();
	}
	else if (strcmp(action_thread, "dump_syscon_testbit") == 0) {
		dump_syscon_testbit();
	}
	else if (strcmp(action_thread, "dump_syscon_notify") == 0) {
		dump_syscon_notify();
	}
	else if (strcmp(action_thread, "dump_sata1_bar") == 0) {
		dump_sata1_bar();
	}
	else if (strcmp(action_thread, "dump_sata2_bar") == 0) {
		dump_sata2_bar();
	}
	else if (strcmp(action_thread, "dump_gelic_bar") == 0) {
		dump_gelic_bar();
	}
	else if (strcmp(action_thread, "dump_encdec_bar") == 0) {
		dump_encdec_bar();
	}
	else if (strcmp(action_thread, "dump_encdec_test") == 0) {
		dump_encdec_test();
	}
	else if (strcmp(action_thread, "dump_encdec_cmd") == 0) {
		dump_encdec_cmd();
	}
	else if (strcmp(action_thread, "dump_usb1_bar") == 0) {
		dump_usb1_bar();
	}
	else if (strcmp(action_thread, "dump_usb2_bar") == 0) {
		dump_usb2_bar();
	}
	else if (strcmp(action_thread, "dump_sata1_bar2") == 0) {
		dump_sata1_bar2();
	}
	else if (strcmp(action_thread, "dump_sata2_bar2") == 0) {
		dump_sata2_bar2();
	}
	else if (strcmp(action_thread, "dump_sata1_bar3") == 0) {
		dump_sata1_bar3();
	}
	else if (strcmp(action_thread, "dump_sata2_bar3") == 0) {
		dump_sata2_bar3();
	}
	else if (strcmp(action_thread, "dump_usb1_bar2") == 0) {
		dump_usb1_bar2();
	}
	else if (strcmp(action_thread, "dump_usb2_bar2") == 0) {
		dump_usb2_bar2();
	}
	else if (strcmp(action_thread, "dump_nor_flash") == 0) {
		dump_nor_flash();
	}
	else if (strcmp(action_thread, "dump_sys_rom") == 0) {
		dump_sys_rom();
	}
	else if (strcmp(action_thread, "dump_avmngr_regs1") == 0) {
		dump_avmngr_regs1();
	}
	else if (strcmp(action_thread, "dump_avmngr_regs2") == 0) {
		dump_avmngr_regs2();
	}
	else if (strcmp(action_thread, "dump_av_outctrl") == 0) {
		dump_av_outctrl();
	}
	else if (strcmp(action_thread, "dump_av_pllctrl") == 0) {
		dump_av_pllctrl();
	}
	else if (strcmp(action_thread, "dump_av_misc1") == 0) {
		dump_av_misc1();
	}
	else if (strcmp(action_thread, "dump_av_misc2") == 0) {
		dump_av_misc2();
	}
	else if (strcmp(action_thread, "dump_av_misc3") == 0) {
		dump_av_misc3();
	}
	else if (strcmp(action_thread, "dump_av_misc4") == 0) {
		dump_av_misc4();
	}
	else if (strcmp(action_thread, "dump_av_misc5") == 0) {
		dump_av_misc5();
	}
	else if (strcmp(action_thread, "dump_gpu_mem1") == 0) {
		dump_gpu_mem1();
	}
	else if (strcmp(action_thread, "dump_gpu_mem2") == 0) {
		dump_gpu_mem2();
	}
	else if (strcmp(action_thread, "dump_gpu_mem3") == 0) {
		dump_gpu_mem3();
	}
	else if (strcmp(action_thread, "dump_gpu_mem4") == 0) {
		dump_gpu_mem4();
	}
	else if (strcmp(action_thread, "dump_gpu_mem5") == 0) {
		dump_gpu_mem5();
	}
	else if (strcmp(action_thread, "dump_rsx_intstate") == 0) {
		dump_rsx_intstate();
	}
	else if (strcmp(action_thread, "dump_ramin_all") == 0) {
		dump_ramin_all();
	}
	else if (strcmp(action_thread, "dump_ramin_hash") == 0) {
		dump_ramin_hash();
	}
	else if (strcmp(action_thread, "dump_ramin_fifo") == 0) {
		dump_ramin_fifo();
	}
	else if (strcmp(action_thread, "dump_dma_objs") == 0) {
		dump_dma_objs();
	}
	else if (strcmp(action_thread, "dump_graph_objs") == 0) {
		dump_graph_objs();
	}
	else if (strcmp(action_thread, "dump_graph_ctx") == 0) {
		dump_graph_ctx();
	}
	else if (strcmp(action_thread, "dump_gameos0") == 0) {
		dump_gameos0();
	}
	else if (strcmp(action_thread, "dump_gameos1") == 0) {
		dump_gameos1();
	}
	else if (strcmp(action_thread, "dump_gameos2") == 0) {
		dump_gameos2();
	}
	else if (strcmp(action_thread, "dump_gameos_htab") == 0) {
		dump_gameos_htab();
	}
	else if (strcmp(action_thread, "dump_all_regions") == 0) {
		dump_all_regions();
	}


	// RSX Overclocking
	/*else if (strcmp(action_thread, "lv1_oc_test_core") == 0)
	{
		OverclockGpuCoreTest();
	}
	else if (strcmp(action_thread, "lv1_oc_test_mem") == 0)
	{
		OverclockGpuMemTest();
	}

	else if (strcmp(action_thread, "lv1_oc_test_all_speeds") == 0)
	{
		TestRsxClockSettings();
	}
	else if (strcmp(action_thread, "lv1_oc_test_safe_speeds") == 0)
	{
		TestRsxClockSettingsSafe();
	}

	// Matched Speeds
	else if (strcmp(action_thread, "set_rsx_clock_100_100") == 0)
	{
		set_rsx_clock_100_100();
	}
	else if (strcmp(action_thread, "set_rsx_clock_150_150") == 0)
	{
		set_rsx_clock_150_150();
	}
	else if (strcmp(action_thread, "set_rsx_clock_200_200") == 0)
	{
		set_rsx_clock_200_200();
	}
	else if (strcmp(action_thread, "set_rsx_clock_250_250") == 0)
	{
		set_rsx_clock_250_250();
	}
	else if (strcmp(action_thread, "set_rsx_clock_300_300") == 0)
	{
		set_rsx_clock_300_300();
	}
	else if (strcmp(action_thread, "set_rsx_clock_350_350") == 0)
	{
		set_rsx_clock_350_350();
	}
	else if (strcmp(action_thread, "set_rsx_clock_400_400") == 0)
	{
		set_rsx_clock_400_400();
	}
	else if (strcmp(action_thread, "set_rsx_clock_450_450") == 0)
	{
		set_rsx_clock_450_450();
	}
	else if (strcmp(action_thread, "set_rsx_clock_500_500") == 0)
	{
		set_rsx_clock_500_500();
	}
	else if (strcmp(action_thread, "set_rsx_clock_550_550") == 0)
	{
		set_rsx_clock_550_550();
	}
	else if (strcmp(action_thread, "set_rsx_clock_600_600") == 0)
	{
		set_rsx_clock_600_600();
	}
	else if (strcmp(action_thread, "set_rsx_clock_650_650") == 0)
	{
		set_rsx_clock_650_650();
	}
	else if (strcmp(action_thread, "set_rsx_clock_700_700") == 0)
	{
		set_rsx_clock_700_700();
	}
	else if (strcmp(action_thread, "set_rsx_clock_750_750") == 0)
	{
		set_rsx_clock_750_750();
	}
	else if (strcmp(action_thread, "set_rsx_clock_800_800") == 0)
	{
		set_rsx_clock_800_800();
	}
	else if (strcmp(action_thread, "set_rsx_clock_850_850") == 0)
	{
		set_rsx_clock_850_850();
	}
	else if (strcmp(action_thread, "set_rsx_clock_900_900") == 0)
	{
		set_rsx_clock_900_900();
	}
	else if (strcmp(action_thread, "set_rsx_clock_950_950") == 0)
	{
		set_rsx_clock_950_950();
	}
	else if (strcmp(action_thread, "set_rsx_clock_1000_1000") == 0)
	{
		set_rsx_clock_1000_1000();
	}

	// RSX Core Clock handlers (100 MHz → 1000 MHz in 50 MHz steps)
	else if (strcmp(action_thread, "set_rsx_core_clock_100") == 0)
	{
		set_rsx_core_clock_100();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_150") == 0)
	{
		set_rsx_core_clock_150();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_200") == 0)
	{
		set_rsx_core_clock_200();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_250") == 0)
	{
		set_rsx_core_clock_250();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_300") == 0)
	{
		set_rsx_core_clock_300();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_350") == 0)
	{
		set_rsx_core_clock_350();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_400") == 0)
	{
		set_rsx_core_clock_400();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_450") == 0)
	{
		set_rsx_core_clock_450();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_500") == 0)
	{
		set_rsx_core_clock_500();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_550") == 0)
	{
		set_rsx_core_clock_550();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_600") == 0)
	{
		set_rsx_core_clock_600();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_650") == 0)
	{
		set_rsx_core_clock_650();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_700") == 0)
	{
		set_rsx_core_clock_700();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_750") == 0)
	{
		set_rsx_core_clock_750();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_800") == 0)
	{
		set_rsx_core_clock_800();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_850") == 0)
	{
		set_rsx_core_clock_850();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_900") == 0)
	{
		set_rsx_core_clock_900();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_950") == 0)
	{
		set_rsx_core_clock_950();
	}
	else if (strcmp(action_thread, "set_rsx_core_clock_1000") == 0)
	{
		set_rsx_core_clock_1000();
	}

	// RSX Memory Clock handlers (100 MHz → 1000 MHz in 25 MHz steps)
	else if (strcmp(action_thread, "set_rsx_mem_clock_100") == 0)
	{
		set_rsx_mem_clock_100();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_125") == 0)
	{
		set_rsx_mem_clock_125();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_150") == 0)
	{
		set_rsx_mem_clock_150();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_175") == 0)
	{
		set_rsx_mem_clock_175();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_200") == 0)
	{
		set_rsx_mem_clock_200();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_225") == 0)
	{
		set_rsx_mem_clock_225();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_250") == 0)
	{
		set_rsx_mem_clock_250();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_275") == 0)
	{
		set_rsx_mem_clock_275();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_300") == 0)
	{
		set_rsx_mem_clock_300();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_325") == 0)
	{
		set_rsx_mem_clock_325();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_350") == 0)
	{
		set_rsx_mem_clock_350();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_375") == 0)
	{
		set_rsx_mem_clock_375();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_400") == 0)
	{
		set_rsx_mem_clock_400();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_425") == 0)
	{
		set_rsx_mem_clock_425();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_450") == 0)
	{
		set_rsx_mem_clock_450();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_475") == 0)
	{
		set_rsx_mem_clock_475();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_500") == 0)
	{
		set_rsx_mem_clock_500();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_525") == 0)
	{
		set_rsx_mem_clock_525();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_550") == 0)
	{
		set_rsx_mem_clock_550();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_575") == 0)
	{
		set_rsx_mem_clock_575();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_600") == 0)
	{
		set_rsx_mem_clock_600();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_625") == 0)
	{
		set_rsx_mem_clock_625();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_650") == 0)
	{
		set_rsx_mem_clock_650();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_675") == 0)
	{
		set_rsx_mem_clock_675();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_700") == 0)
	{
		set_rsx_mem_clock_700();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_725") == 0)
	{
		set_rsx_mem_clock_725();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_750") == 0)
	{
		set_rsx_mem_clock_750();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_775") == 0)
	{
		set_rsx_mem_clock_775();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_800") == 0)
	{
		set_rsx_mem_clock_800();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_825") == 0)
	{
		set_rsx_mem_clock_825();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_850") == 0)
	{
		set_rsx_mem_clock_850();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_875") == 0)
	{
		set_rsx_mem_clock_875();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_900") == 0)
	{
		set_rsx_mem_clock_900();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_925") == 0)
	{
		set_rsx_mem_clock_925();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_950") == 0)
	{
		set_rsx_mem_clock_950();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_975") == 0)
	{
		set_rsx_mem_clock_975();
	}
	else if (strcmp(action_thread, "set_rsx_mem_clock_1000") == 0)
	{
		set_rsx_mem_clock_1000();
	}*/
	
	/*
	// NoPSN Patches
	else if (strcmp(action_thread, "nopsn_amazon") == 0)
	{
		// Amazon vshnet_sceLoginServiceGetNpStatus
		uint32_t patch1 = 0x38600001;
		uint32_t patch2 = 0x4E800020;
		poke_vsh(0x242458, (char*)&patch1, 4);
		poke_vsh(0x24245C, (char*)&patch2, 4);
		notify("NoPSN Patch Applied For Amazon", 0, 0, 0, 0, false);
	}
	else if (strcmp(action_thread, "nopsn_hulu") == 0)
	{
		// Hulu
		// 0x24557C
		uint32_t patch1 = 0x2F800001;
		//uint32_t patch2 = 0x4E800020;
		poke_vsh(0x242C10, (char*)&patch1, 4);
		//poke_vsh(0x245580, (char*)&patch2, 4);
		notify("NoPSN Patch Applied For Hulu", 0, 0, 0, 0, false);
	}
	else if (strcmp(action_thread, "nopsn_youtube") == 0)
	{
		// Youtube vshnet_sceNpGetStatus
		uint32_t patch = 0x2F800001;
		poke_vsh(0x1B60A4, (char*)&patch, 4);
		notify("NoPSN Patch Applied For Youtube", 0, 0, 0, 0, false);
	}
	else if (strcmp(action_thread, "nopsn_test") == 0)
	{
		// TEST ONLY


		// 001B6080 _Export_vshnet_sceNpGetStatus
		// Allows YouTube to work
		uint32_t patch1a = 0x38600001;
		uint32_t patch1b = 0x4E800020;
		uint32_t addr1a = 0x1B6080;
		uint32_t addr1b = 0x1B6084;
		poke_vsh(addr1a, (char*)&patch1a, 4);
		poke_vsh(addr1b, (char*)&patch1b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpGetStatus: 0x%08X / %08X\n_Export_vshnet_sceNpGetStatus: 0x%08X / %08X\n", addr1a, patch1a, addr1b, patch1b, false);

		// 000F54E8 UNK_MANAGER_SIGNOUT
		uint32_t patch2a = 0x38600000;
		uint32_t patch2b = 0x4E800020;
		uint32_t addr2a = 0xF54E8;
		uint32_t addr2b = 0xF54EC;
		poke_vsh(addr2a, (char*)&patch2a, 4);
		poke_vsh(addr2b, (char*)&patch2b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_MANAGER_SIGNOUT: 0x%08X / %08X\nUNK_MANAGER_SIGNOUT: 0x%08X / %08X\n", addr2a, patch2a, addr2b, patch2b, false);

		// Loop
		// 002774D8                 bne       cr7, UNK_NP_GET_STATUS
		uint32_t patch3a = 0x60000000;
		uint32_t addr3a = 0x2774D8;
		poke_vsh(addr3a, (char*)&patch3a, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nbne       cr7, UNK_NP_GET_STATUS: 0x%08X / %08X\n", addr3a, patch3a, false);

		// 001B7C18 _Export_vshnet_sceNpGetNpId
		uint32_t patch4a = 0x38600001;
		uint32_t patch4b = 0x4E800020;
		uint32_t addr4a = 0x1B7C18;
		uint32_t addr4b = 0x1B7C1C;
		poke_vsh(addr4a, (char*)&patch4a, 4);
		poke_vsh(addr4b, (char*)&patch4b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpGetNpId: 0x%08X / %08X\n_Export_vshnet_sceNpGetNpId: 0x%08X / %08X\n", addr4a, patch4a, addr4b, patch4b, false);

		// 002439BC _Export_vshnet_sceLoginServiceInit
		uint32_t patch5a = 0x38600001;
		uint32_t patch5b = 0x4E800020;
		uint32_t addr5a = 0x2439BC;
		uint32_t addr5b = 0x2439C0;
		poke_vsh(addr5a, (char*)&patch5a, 4);
		poke_vsh(addr5b, (char*)&patch5b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceInit: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceInit: 0x%08X / %08X\n", addr5a, patch5b, addr5a, patch5b, false);

		// 002438CC _Export_vshnet_sceLoginServiceLocalLogin
		uint32_t patch6a = 0x38600000;
		uint32_t patch6b = 0x4E800020;
		uint32_t addr6a = 0x2438CC;
		uint32_t addr6b = 0x2438D0;
		poke_vsh(addr6a, (char*)&patch6a, 4);
		poke_vsh(addr6b, (char*)&patch6b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceLocalLogin: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceLocalLogin: 0x%08X / %08X\n", addr6a, patch6b, addr6a, patch6b, false);

		// 00242F1C _Export_vshnet_sceLoginServiceLocalLogout
		uint32_t patch7a = 0x38600000;
		uint32_t patch7b = 0x4E800020;
		uint32_t addr7a = 0x242F1C;
		uint32_t addr7b = 0x242F20;
		poke_vsh(addr7a, (char*)&patch7a, 4);
		poke_vsh(addr7b, (char*)&patch7b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceLocalLogout: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceLocalLogout: 0x%08X / %08X\n", addr7a, patch7a, addr7b, patch7b, false);

		// 00242CC0 _Export_vshnet_sceLoginServiceNetworkLogin
		uint32_t patch8a = 0x38600001;// 0 prevents signin / 1 gives error 0x00000001, some apps load, ie Amazon
		uint32_t patch8b = 0x4E800020;
		uint32_t addr8a = 0x242CC0;
		uint32_t addr8b = 0x242CC4;
		poke_vsh(addr8a, (char*)&patch8a, 4);
		poke_vsh(addr8b, (char*)&patch8b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceNetworkLogin: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceNetworkLogin: 0x%08X / %08X\n", addr8a, patch8a, addr8b, patch8b, false);

		// 00242BF0 _Export_vshnet_sceLoginServiceNetworkLogout
		uint32_t patch9a = 0x38600000;
		uint32_t patch9b = 0x4E800020;
		uint32_t addr9a = 0x242BF0;
		uint32_t addr9b = 0x242BF4;
		poke_vsh(addr9a, (char*)&patch9a, 4);
		poke_vsh(addr9b, (char*)&patch9b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceNetworkLogout: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceNetworkLogout: 0x%08X / %08X\n", addr9a, patch9a, addr9b, patch9b, false);

		// 002438D4 _Export_vshnet_sceLoginServiceTerm
		uint32_t patch10a = 0x38600001;
		uint32_t patch10b = 0x4E800020;
		uint32_t addr10a = 0x2438D4;
		uint32_t addr10b = 0x2438D8;
		poke_vsh(addr10a, (char*)&patch10a, 4);
		poke_vsh(addr10b, (char*)&patch10b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceTerm: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceTerm: 0x%08X / %08X\n", addr10a, patch10a, addr10b, patch10b, false);

		// 001B34DC _Export_vshnet_sceNpLogin
		uint32_t patch11a = 0x38600001;
		uint32_t patch11b = 0x4E800020;
		uint32_t addr11a = 0x1B34DC;
		uint32_t addr11b = 0x1B34E0;
		poke_vsh(addr11a, (char*)&patch11a, 4);
		poke_vsh(addr11b, (char*)&patch11b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n", addr11a, patch11a, addr11b, patch11b, false);

		// 001B44B8 _Export_vshnet_sceNpLogin2
		uint32_t patch12a = 0x38600001;
		uint32_t patch12b = 0x4E800020;
		uint32_t addr12a = 0x1B44B8;
		uint32_t addr12b = 0x1B44BC;
		poke_vsh(addr12a, (char*)&patch12a, 4);
		poke_vsh(addr12b, (char*)&patch12b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n", addr12a, patch12a, addr12b, patch12b, false);

		// 001B43BC _Export_vshnet_sceNpLogout
		uint32_t patch13a = 0x38600000;
		uint32_t patch13b = 0x4E800020;
		uint32_t addr13a = 0x1B43BC;
		uint32_t addr13b = 0x1B43C0;
		poke_vsh(addr13a, (char*)&patch13a, 4);
		poke_vsh(addr13b, (char*)&patch13b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n", addr13a, patch13a, addr13b, patch13b, false);

		// 002452AC UNK_NP_ONLINE_0
		// Setting to return 1 in r3 breaks some shit!
		// if you sign in to psn, it forces a signin msg loop on xmb and loading friendim assets (PSN Store Icon blinks)
		uint32_t patch14a = 0x38600001;
		uint32_t patch14b = 0x4E800020;
		uint32_t addr14a = 0x2452AC;
		uint32_t addr14b = 0x2452B0;
		poke_vsh(addr14a, (char*)&patch14a, 4);
		poke_vsh(addr14b, (char*)&patch14b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_NP_ONLINE_0: 0x%08X / %08X\nUNK_NP_ONLINE_0: 0x%08X / %08X\n", addr14a, patch14a, addr14b, patch14b, false);

		// 002452FC                 ble       cr7, UNK_NP_ONLINE_1
		// Original bytes:  40 9D 01 00
		// crashes ps3 when you sign in
		uint32_t patch15a = 0x4B9D0100;
		uint32_t addr15a = 0x2452FC;
		poke_vsh(addr15a, (char*)&patch15a, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_NP_ONLINE_1: 0x%08X / %08X\nUNK_NP_ONLINE_1: 0x%08X / %08X\n", addr15a, patch15a, false);

		// 00244AC0 UNK_NP_ONLINE_3
		// blocks signin to psn?
		uint32_t patch16a = 0x38600001;
		uint32_t patch16b = 0x4E800020;
		uint32_t addr16a = 0x244AC0;
		uint32_t addr16b = 0x244AC0;
		poke_vsh(addr16a, (char*)&patch16a, 4);
		poke_vsh(addr16b, (char*)&patch16b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_NP_ONLINE_3: 0x%08X / %08X\nUNK_NP_ONLINE_3: 0x%08X / %08X\n", addr16a, patch16a, addr16b, patch16b, false);

		// unk
		uint32_t patch17a = 0x38600001;
		uint32_t patch17b = 0x4E800020;
		uint32_t addr17a = 0x244AC0;
		uint32_t addr17b = 0x244AC0;
		poke_vsh(addr17a, (char*)&patch17a, 4);
		poke_vsh(addr17b, (char*)&patch17b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_NP_ONLINE_3: 0x%08X / %08X\nUNK_NP_ONLINE_3: 0x%08X / %08X\n", addr17a, patch17a, addr17b, patch17b, false);



	}
	else if (strcmp(action_thread, "reset_psn_patches") == 0)
	{
		reset_psn_patches();
		notify("NoPSN Patches Reset", 0, 0, 0, 0, false);
	}

	// Kernel Patches
	else if (strcmp(action_thread, "kernel_setfw_version_482") == 0)
	{
		kpatch(0x80000000002FCB68ULL, 0x323031372F30382FULL);
	}
	else if (strcmp(action_thread, "kernel_setfw_version_484") == 0)
	{
		kpatch(0x80000000002FCB68ULL, 0x323031392F30312FULL);
	}
	else if (strcmp(action_thread, "kernel_setfw_version_485") == 0)
	{
		kpatch(0x80000000002FCB68ULL, 0x323031392F30372FULL);
	}
	else if (strcmp(action_thread, "kernel_setfw_version_486") == 0)
	{
		kpatch(0x80000000002FCB68ULL, 0x323032302F30312FULL);
	}
	*/


	/*
	// EvilNat defaults
	// Shutdown options
	if(strcmp(action_thread, "shutdown_action") == 0)	
		rebootXMB(SYS_SHUTDOWN);	
	else if(strcmp(action_thread, "soft_reboot_action") == 0)	
		rebootXMB(SYS_SOFT_REBOOT);
	else if(strcmp(action_thread, "hard_reboot_action") == 0)	
		rebootXMB(SYS_HARD_REBOOT);
	else if(strcmp(action_thread, "lv2_reboot_action") == 0)	
		rebootXMB(SYS_LV2_REBOOT);

	// Cobra options	
	else if(strcmp(action_thread, "cobra_info") == 0)	
		show_cobra_info();
	else if(strcmp(action_thread, "check_syscall8") == 0)	
		checkSyscall(SC_COBRA_SYSCALL8);		
	else if(strcmp(action_thread, "create_rif_license") == 0)	
		create_rifs();		
	else if(strcmp(action_thread, "create_syscalls") == 0)	
		create_syscalls();
	else if(strcmp(action_thread, "enable_ftp") == 0)
		load_ftp();
	else if(strcmp(action_thread, "disable_ftp") == 0)
		unload_ftp();
	else if(strcmp(action_thread, "toggle_trophy_unlocker") == 0)
		toggle_trophy_unlocker();
	else if(strcmp(action_thread, "allow_restore_sc") == 0)	
		allow_restore_sc();	
	else if(strcmp(action_thread, "skip_existing_rif") == 0)	
		skip_existing_rif();	
	else if(strcmp(action_thread, "enable_whatsnew") == 0)	
		enable_WhatsNew();
	else if(strcmp(action_thread, "toggle_external_cobra") == 0)	
		toggle_external_cobra();	
	else if(strcmp(action_thread, "cobra_version") == 0)
	{		
		if(toggle_cobra_version() == CELL_OK)
		{
			wait(2);
			rebootXMB(SYS_HARD_REBOOT);
		}
	}
	else if(strcmp(action_thread, "cobra_mode") == 0)
	{
		if(toggle_cobra() == CELL_OK)
		{
			wait(2);
			rebootXMB(SYS_HARD_REBOOT);
		}
	}
	else if(strcmp(action_thread, "toggle_plugins") == 0)
		toggle_plugins();
	else if(strcmp(action_thread, "toggle_npsignin_lck") == 0)	
		toggle_npsignin_lck();
	else if(strcmp(action_thread, "toggle_ofw_mode") == 0)	
		toggle_ofw_mode();
	else if(strcmp(action_thread, "toggle_ps2_icon") == 0)	
		toogle_PS2_disc_icon();
	else if(strcmp(action_thread, "toggle_gameboot") == 0)	
		toggle_gameboot();
	else if(strcmp(action_thread, "toggle_coldboot_animation") == 0)	
		toggle_coldboot_animation();
	else if(strcmp(action_thread, "toggle_epilepsy_warning") == 0)	
		toggle_epilepsy_warning();
	else if(strcmp(action_thread, "toggle_hidden_trophy_patch") == 0)	
		toggle_hidden_trophy_patch();

	// PSN Tools
	else if(strcmp(action_thread, "disable_syscalls") == 0)	
		removeSysHistory();		
	else if(strcmp(action_thread, "spoof_targetid") == 0)	
		spoof_with_eid5();	
	else if(strcmp(action_thread, "spoof_idps") == 0)	
		spoof_idps();
	else if(strcmp(action_thread, "spoof_psid") == 0)	
		spoof_psid();
	else if(strcmp(action_thread, "spoof_mac") == 0)	
		spoof_mac();
	else if(strcmp(action_thread, "show_accountid") == 0)
		getAccountID();		
	else if(strcmp(action_thread, "set_accountid") == 0)
		changeAccountID(WRITE, 0);
	else if(strcmp(action_thread, "set_accountid_overwrite") == 0)
		changeAccountID(WRITE, 1);
	else if(strcmp(action_thread, "remove_accountid") == 0)
		changeAccountID(EMPTY, 1);
	else if(strcmp(action_thread, "activate_account") == 0)	
		activate_account();	
	else if(strcmp(action_thread, "backup_license") == 0)
		backup_license();
	else if(strcmp(action_thread, "remove_license") == 0)
		remove_license();
	else if(strcmp(action_thread, "patch_savedata") == 0)	
		patch_savedata();	

	// Fan Modes
	else if(strcmp(action_thread, "fan_mode_disabled") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_DISABLED) == 0)			
			showMessage("msg_cobra_fan_mode_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_syscon") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_SYSCON) == 0)
			showMessage("msg_cobra_fan_mode_syscon", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_max") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MAX) == 0)
			showMessage("msg_cobra_fan_mode_max", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	// Dynamic Modes
	else if(strcmp(action_thread, "fan_mode_60") == 0)	
	{
		if(save_cobra_fan_cfg(DYNAMIC_FAN_60) == 0)
			showMessage("msg_cobra_fan_dynamic_60", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_65") == 0)	
	{
		if(save_cobra_fan_cfg(DYNAMIC_FAN_65) == 0)
			showMessage("msg_cobra_fan_dynamic_65", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_70") == 0)	
	{
		if(save_cobra_fan_cfg(DYNAMIC_FAN_70) == 0)
			showMessage("msg_cobra_fan_dynamic_70", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_mode_75") == 0)	
	{
		if(save_cobra_fan_cfg(DYNAMIC_FAN_75) == 0)
			showMessage("msg_cobra_fan_dynamic_75", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	// Manual Modes
	else if(strcmp(action_thread, "fan_manual_40") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_40) == 0)
			showMessage("msg_cobra_fan_manual_40", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_45") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_45) == 0)
			showMessage("msg_cobra_fan_manual_45", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_50") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_50) == 0)
			showMessage("msg_cobra_fan_manual_50", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_55") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_55) == 0)
			showMessage("msg_cobra_fan_manual_55", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_60") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_60) == 0)
			showMessage("msg_cobra_fan_manual_60", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_65") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_65) == 0)
			showMessage("msg_cobra_fan_manual_65", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_70") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_70) == 0)
			showMessage("msg_cobra_fan_manual_70", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_75") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_75) == 0)
			showMessage("msg_cobra_fan_manual_75", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_80") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_80) == 0)
			showMessage("msg_cobra_fan_manual_80", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_85") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_85) == 0)
			showMessage("msg_cobra_fan_manual_85", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_90") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_90) == 0)
			showMessage("msg_cobra_fan_manual_90", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_manual_95") == 0)	
	{
		if(save_cobra_fan_cfg(FAN_MANUAL_95) == 0)
			showMessage("msg_cobra_fan_manual_95", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	// PS2 Fan modes
	else if(strcmp(action_thread, "fan_ps2mode_disabled") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_DISABLED) == 0)
			showMessage("msg_cobra_fan_ps2mode_disabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_syscon") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_SYSCON) == 0)
			showMessage("msg_cobra_fan_ps2mode_syscon", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_40") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_40) == 0)
			showMessage("msg_cobra_fan_ps2mode_40", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_50") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_50) == 0)
			showMessage("msg_cobra_fan_ps2mode_50", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_60") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_60) == 0)
			showMessage("msg_cobra_fan_ps2mode_60", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_70") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_70) == 0)
			showMessage("msg_cobra_fan_ps2mode_70", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_80") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_80) == 0)
			showMessage("msg_cobra_fan_ps2mode_80", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}
	else if(strcmp(action_thread, "fan_ps2mode_90") == 0)	
	{
		if(save_ps2_fan_cfg(FAN_PS2_90) == 0)
			showMessage("msg_cobra_fan_ps2mode_90", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	}

	// Basic options	
	else if(strcmp(action_thread, "ps3_lifetime") == 0)	
		getPS3Lifetime();
	else if(strcmp(action_thread, "fan_data") == 0)	
		get_temperature_data();	
	else if(strcmp(action_thread, "show_ids") == 0)	
		show_ids();	
	else if(strcmp(action_thread, "show_ip") == 0)	
		show_ip();
	else if(strcmp(action_thread, "decrypt_redump_isos_hdd") == 0)	
		decryptRedumpISO(0);
	else if(strcmp(action_thread, "decrypt_redump_isos_usb") == 0)	
		decryptRedumpISO(1);
	else if(strcmp(action_thread, "rap2bin") == 0)	
		rap2bin();
	else if(strcmp(action_thread, "bin2rap") == 0)	
		bin2rap();
	else if(strcmp(action_thread, "cbomb") == 0)	
		Fix_CBOMB();
	else if(strcmp(action_thread, "show_clocks") == 0)	
		getClockSpeeds();
	else if(strcmp(action_thread, "toggle_dlna") == 0)	
		toggle_dlna();	
	else if(strcmp(action_thread, "toggle_coldboot") == 0)
		toggle_coldboot();	
	else if(strcmp(action_thread, "toggle_bt_audio") == 0)
		swap_libaudio();	
	else if(strcmp(action_thread, "show_bd_info") == 0)	
		show_bd_info();	
	else if(strcmp(action_thread, "show_version") == 0)
		notify(XAI_VERSION);

	//else if(strcmp(action_thread, "toggle_sysconf_rco") == 0)
	//{
	//	CellFsStat statinfo;
	//
	//	if(toggle_sysconf() == CELL_OK)
	//		showMessage((cellFsStat("/dev_flash/vsh/resource/sysconf_plugin.rco.ori", &statinfo) == CELL_OK) ? "msg_mod_sysconf_enabled" : "msg_ori_sysconf_enabled", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	//}

	// Buzzer Options
	else if(strcmp(action_thread, "buzzer_single") == 0)
		buzzer(SINGLE_BEEP);
	else if(strcmp(action_thread, "buzzer_double") == 0)
		buzzer(DOUBLE_BEEP);
	else if(strcmp(action_thread, "buzzer_triple") == 0)
		buzzer(TRIPLE_BEEP);
	else if(strcmp(action_thread, "buzzer_continuous") == 0)
		buzzer(CONTINUOUS_BEEP);	

	// CEX2DEX Options
	else if(strcmp(action_thread, "convert_cex") == 0)
		cex2dex(CEX_TO_DEX);
	else if(strcmp(action_thread, "convert_dex") == 0)
		cex2dex(DEX_TO_CEX);
	else if(strcmp(action_thread, "swap_kernel") == 0)
		swapKernel();
	else if(strcmp(action_thread, "check_targetid") == 0)			
		getTargetID(0);
	else if(strcmp(action_thread, "swap_ip_xmb") == 0)			
		toggle_xmbplugin();
	else if(strcmp(action_thread, "toggle_vsh") == 0)			
		toggle_vsh();
	else if(strcmp(action_thread, "toggle_sysconf") == 0)			
		toggle_sysconf();
	else if(strcmp(action_thread, "cex2dex_showinfo") == 0)
		get_ps3_info();

	// Led Options
	else if(strcmp(action_thread, "set_led_off") == 0)
		setLed("ledOff");
	else if(strcmp(action_thread, "set_led_red") == 0) 
		setLed("ledRed_default");
	else if(strcmp(action_thread, "set_led_red_slow") == 0) 
		setLed("ledRed_blink_slow");
	else if(strcmp(action_thread, "set_led_red_fast") == 0) 
		setLed("ledRed_blink_fast");
	else if(strcmp(action_thread, "set_led_green") == 0) 
		setLed("ledGreen_default");
	else if(strcmp(action_thread, "set_led_green_slow") == 0) 
		setLed("ledGreen_blink_slow");
	else if(strcmp(action_thread, "set_led_green_fast") == 0) 
		setLed("ledGreen_blink_fast");
	else if(strcmp(action_thread, "set_led_yellow") == 0) 
		setLed("ledYellow_default");
	else if(strcmp(action_thread, "set_led_yellow_slow") == 0) 
		setLed("ledYellow_blink_slow");
	else if(strcmp(action_thread, "set_led_yellow_fast") == 0) 
		setLed("ledYellow_blink_fast");
	else if(strcmp(action_thread, "set_led_yellowg_slow") == 0) 
		setLed("ledYellowG_blink_slow");
	else if(strcmp(action_thread, "set_led_yellowg_fast") == 0) 
		setLed("ledYellowG_blink_fast");
	else if(strcmp(action_thread, "set_led_yellowr_slow") == 0) 
		setLed("ledYellowR_blink_slow");
	else if(strcmp(action_thread, "set_led_yellowr_fast") == 0) 
		setLed("ledYellowR_blink_fast");
	else if(strcmp(action_thread, "set_led_rainbow") == 0) 
		setLed("rainbow");
	else if(strcmp(action_thread, "set_led_special1") == 0) 
		setLed("special1");
	else if(strcmp(action_thread, "set_led_special2") == 0) 
		setLed("special2");

	// QA options
	else if(strcmp(action_thread, "check_qa") == 0)
		read_qa_flag();
	else if(strcmp(action_thread, "enable_qa_normal") == 0)
		set_qa(BASIC);
	else if(strcmp(action_thread, "enable_qa_advanced") == 0)
		set_qa(FULL);
	else if(strcmp(action_thread, "disable_qa") == 0)
		set_qa(DISABLE);

	// xRegistry options	
	else if(strcmp(action_thread, "backup_registry") == 0)	
		backup_registry();	
	else if(strcmp(action_thread, "toggle_dvdtvsys") == 0)	
		toggle_dvdtvsys();		
	else if(strcmp(action_thread, "button_assignment") == 0)
		button_assignment();	

	else if(strcmp(action_thread, "set_region_japan") == 0)
		set_region(0x83, 2, 1, 2);
	else if(strcmp(action_thread, "set_region_usa") == 0)
		set_region(0x84, 1, 1, 2);
	else if(strcmp(action_thread, "set_region_eur") == 0)
		set_region(0x85, 2, 2, 2);
	else if(strcmp(action_thread, "set_region_korea") == 0)
		set_region(0x86, 3, 1, 2);
	else if(strcmp(action_thread, "set_region_uk") == 0)
		set_region(0x87, 2, 2, 2);
	else if(strcmp(action_thread, "set_region_mexico") == 0)
		set_region(0x88, 4, 1, 2);
	else if(strcmp(action_thread, "set_region_australia") == 0)
		set_region(0x89, 4, 2, 2);
	else if(strcmp(action_thread, "set_region_asia") == 0)
		set_region(0x8A, 3, 1, 2);
	else if(strcmp(action_thread, "set_region_taiwan") == 0)
		set_region(0x8B, 3, 1, 2);
	else if(strcmp(action_thread, "set_region_russia") == 0)
		set_region(0x8C, 5, 4, 2);
	else if(strcmp(action_thread, "set_region_china") == 0)
		set_region(0x8D, 6, 4, 2);
	else if(strcmp(action_thread, "set_region_hongkong") == 0)
		set_region(0x8E, 3, 1, 2);
	else if(strcmp(action_thread, "set_region_brazil") == 0)
		set_region(0x8F, 4, 1, 2);
	else if(strcmp(action_thread, "set_region_default") == 0)
		set_region_default();
	else if(strcmp(action_thread, "check_region_values") == 0)
		check_region_values();

	// Rebug options	
	//else if(strcmp(action_thread, "normal_mode") == 0)	
	//{
	//	if(normal_mode() == CELL_OK)
	//	{
	//		showMessage("msg_normal_mode", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
	//		wait(2);
	//		rebootXMB(SYS_SOFT_REBOOT);
	//	}
	//}
	else if(strcmp(action_thread, "rebug_mode") == 0)	
	{
		if(rebug_mode() == CELL_OK)
		{
			showMessage("msg_rebug_mode", (char *)XAI_PLUGIN, (char *)TEX_SUCCESS);
			wait(2);
			rebootXMB(SYS_SOFT_REBOOT);
		}
	}
	else if(strcmp(action_thread, "debugsettings_mode") == 0)		
		debugsettings_mode();	
	else if(strcmp(action_thread, "xmb_plugin") == 0)	
	{
		if(toggle_xmb_plugin() == CELL_OK)
		{
			wait(3);
			rebootXMB(SYS_SOFT_REBOOT);
		}
	}
	else if(strcmp(action_thread, "xmb_mode") == 0)	
	{
		if(toggle_xmb_mode() == CELL_OK)
		{
			wait(3);
			rebootXMB(SYS_SOFT_REBOOT);
		}
	}
	//else if(strcmp(action_thread, "download_toolbox") == 0)	
	//	download_toolbox();
	//else if(strcmp(action_thread, "install_toolbox") == 0)	
	//	install_toolbox();

	// Advanced Tools options
	else if(strcmp(action_thread, "rsod_fix") == 0)
	{		
		if(rsod_fix() == true)
			rebootXMB(SYS_HARD_REBOOT);
	}	
	else if(strcmp(action_thread, "service_mode") == 0)
	{
		if(!service_mode())
			rebootXMB(SYS_HARD_REBOOT);
	}	
	else if(strcmp(action_thread, "remarry_bd") == 0)			
		remarry_bd();	
	else if(strcmp(action_thread, "check_ros_bank") == 0)			
		check_ros_bank();	
	else if(strcmp(action_thread, "check_8th_spe") == 0)			
		check_8th_spe();	
	else if(strcmp(action_thread, "toggle_8th_spe") == 0)			
		toggle_8th_spe();
	else if(strcmp(action_thread, "patch_prodg") == 0)	
		Patch_ProDG();
	else if(strcmp(action_thread, "enable_dex_support") == 0)	
		enable_dex_support();
	else if(strcmp(action_thread, "disable_dex_support") == 0)	
		disable_dex_support();
	else if(strcmp(action_thread, "toggle_devblind") == 0)			
		toggle_devblind();	
	else if(strcmp(action_thread, "load_kernel") == 0)	
		loadKernel();	
	
	// Dump Tools options	
	else if(strcmp(action_thread, "clean_log") == 0)	
		clean_log();
	else if(strcmp(action_thread, "export_rap") == 0)	
		export_rap();
	else if(strcmp(action_thread, "dump_ids") == 0)	
		dump_ids();	
	else if(strcmp(action_thread, "dump_erk") == 0)	
		dumpERK(ERK);		
	else if(strcmp(action_thread, "dump_metldr") == 0)	
		dumpERK(METLDR);	
	else if(strcmp(action_thread, "dump_lv2") == 0)	
		dump_lv(LV2);		
	else if(strcmp(action_thread, "dump_lv1") == 0)	
		dump_lv(LV1);
	else if(strcmp(action_thread, "dump_ram") == 0)	
		dump_lv(RAM);
	else if(strcmp(action_thread, "dump_sysrom") == 0)	
		dump_sysrom();
	else if(strcmp(action_thread, "dump_eeprom") == 0)	
		dump_eeprom();
	else if(strcmp(action_thread, "dump_syscon_log") == 0)	
		sm_error_log();
	else if(strcmp(action_thread, "get_token_seed") == 0)	
		get_token_seed();
	else if(strcmp(action_thread, "dump_flash") == 0)	
		dumpFlash();
	else if(strcmp(action_thread, "log_klic") == 0)	
		log_klic();	
	else if(strcmp(action_thread, "log_secureid") == 0)	
		log_secureid();	
	else if(strcmp(action_thread, "dump_disc_key") == 0)	
		dump_disc_key();

	// Rebug Toolbox
	//
	// Contains data for different versions of FW
	// It is possible that support for some more may need to be added
	//
 	else if(strcmp(action_thread, "rbt_pp") == 0)	
		rtb_pp();
	else if(strcmp(action_thread, "rbt_lv2") == 0)	
	{
		if(rbt_custom_lv1_patch(0x3BA000002F830033ULL, 0x2B0000, 0x2C0000, 0x419E0118, 0x60000000, 8) == 2)
			offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_htab") == 0)	
	{
		if(rbt_custom_lv1_patch(0x41DC00543D409979ULL, 0x2D0000, 0x2F0000, 0x41DA0054, 0x60000000, 8) == 2)
			offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_indi") == 0)	
	{
		if(rbt_custom_lv1_patch(0x3860000D3800000DULL, 0xAC000, 0x100000, 0x7C630038, 0x38600000, 8) == 2)
			if(rbt_custom_lv1_patch(0x3860000D3800000DULL, 0x1B0000, 0x1C0000, 0x7C630038, 0x38600000, 8) == 2)
				offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_um") == 0)	
	{
		if(rbt_custom_lv1_patch(0x7FC3F3784802D40DULL, 0xFA000, 0xFF000, 0xE8180008, 0x38000000, 8) == 2)
			if(rbt_custom_lv1_patch(0x7FC3F3784802D40DULL, 0x700000, 0x710000, 0xE8180008, 0x38000000, 8) == 2)
				offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_dm") == 0)	
		rtb_dm();
	else if(strcmp(action_thread, "rbt_enc") == 0)	
	{
		if(rbt_custom_lv1_patch(0x3BFEFF7F2B9F0008ULL, 0x270000, 0x280000, 0x392001CF, 0x392001DF, 0x10) == 2)
			offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_smgo") == 0)	
		rtb_smgo();
	else if(strcmp(action_thread, "rbt_pkg") == 0)	
	{
		if(rbt_custom_lv1_patch(0xFBC10070480301D1ULL, 0xF0000, 0x120000, 0x419D00A8, 0x60000000, 0x1C) == 2)
			if(rbt_custom_lv1_patch(0xFBC10070480301D1ULL, 0x700000, 0x800000, 0x419D00A8, 0x60000000, 0x1C) == 2)
				offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_lpar") == 0)	
		rtb_lpar();
	else if(strcmp(action_thread, "rbt_spe") == 0)	
	{
		if(rbt_custom_lv1_patch(0xF80300307D034378ULL, 0x2F0000, 0x300000, 0x39200009, 0x3920FFFF, 0x10) == 2)
			offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_dabr") == 0)	
	{
		if(rbt_custom_lv1_patch(0x7C9F23784BD172ADULL, 0x2EA000, 0x300000, 0x3800000B, 0x3800000F, 0x60) == 2)
			offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_gart") == 0)	
	{
		if(rbt_custom_lv1_patch(0xF92301A8419E000CULL, 0x210000, 0x230000, 0x3C000001, 0x38001000, 8) == 2)
			offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_keys") == 0)	
	{
		if(rbt_custom_lv1_patch(0x2BA9000338000009ULL, 0x710000, 0x720000, 0x419D004C, 0x60000000, 8) == 2)
			offsetNotfound();
	}
	else if(strcmp(action_thread, "rbt_acl") == 0)	
		rtb_acl();
	else if(strcmp(action_thread, "rbt_go") == 0)	
		rtb_go();

	// OtherOS options
	else if(strcmp(action_thread, "otheros_resize") == 0)	
	{
		if(check_flash_type())
			setup_vflash();
		else
			setup_flash();
	}
	else if(strcmp(action_thread, "otheros_petitboot") == 0)
		install_petitboot();
	else if(strcmp(action_thread, "otheros_flag") == 0)
		set_flag(OTHEROS_FLAG);
	else if(strcmp(action_thread, "gameos_flag") == 0)
		set_flag(GAMEOS_FLAG);
	
	// Recovery options
	else if(strcmp(action_thread, "applicable_version") == 0)	
		applicable_version();	
	else if(strcmp(action_thread, "fs_check") == 0)	
		sys_sm_shutdown(SYS_SOFT_REBOOT);
	else if(strcmp(action_thread, "rebuild_db") == 0)
		rebuild_db();
	else if(strcmp(action_thread, "toggle_hdd_space") == 0)
		unlock_hdd_space();
	else if(strcmp(action_thread, "recovery_mode") == 0)
		recovery_mode();
			
	// Unused options
	//else if(strcmp(action_thread, "enable_screenshot") == 0)			
	//	enable_screenshot();		
	//else if(strcmp(action_thread, "enable_recording") == 0)	
	//	enable_recording();	
	//else if(strcmp(action_thread, "override_sfo") == 0)		
	//	override_sfo();					
	//else if(strcmp(action_thread, "enable_hvdbg") == 0)
	//{
	//	if(enable_hvdbg() == true)
	//		rebootXMB(SYS_HARD_REBOOT);
	//}
	//else if(strcmp(action_thread, "usb_firm_loader") == 0)	
	//	usb_firm_loader();
	*/
	
	sys_ppu_thread_exit(0);
}

void xai_plugin_interface_action::xai_plugin_action(const char * action)
{	
	thread_id = 0;

	log_function("xai_plugin", __VIEW__, __FUNCTION__, "(%s)\n", action);
	action_thread = action;
	sys_ppu_thread_create(&thread_id, plugin_thread, 0, 3000, 0x4000, 0, "xai_thread");
}
