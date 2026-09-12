extern bool qcfw_is_exploited();

extern bool qcfw_is_nor();
extern bool qcfw_is_emmc();

extern bool qcfw_dump_nor_to_file(uint32_t offset, uint32_t size, const char* filePath, uint32_t chunk_size);
extern bool qcfw_dump_emmc_to_file(uint64_t offset, uint64_t size, const char* filePath, uint32_t chunk_size);

extern bool qcfw_install_stagex(bool showSuccess);
extern bool qcfw_install_qcfw();

extern bool qcfw_dump_nor_to_usb();

extern bool qcfw_dump_emmc_to_usb_256M();
extern bool qcfw_dump_emmc_to_usb_12G();