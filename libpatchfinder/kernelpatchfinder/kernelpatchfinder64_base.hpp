//
//  kernelpatchfinder64_base.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 20.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#ifndef kernelpatchfinder64_base_hpp
#define kernelpatchfinder64_base_hpp

#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder64.hpp>

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_base : public kernelpatchfinder64{
        
    public:
        kernelpatchfinder64_base(const char *filename);
        kernelpatchfinder64_base(const void *buffer, size_t bufSize, bool takeOwnership = false);
        kernelpatchfinder64_base(kernelpatchfinder64 &&mv);
        virtual ~kernelpatchfinder64_base() override;
                
#pragma mark Location finders
        virtual loc_t find_syscall0() override;
        virtual loc_t find_machtrap_table() override;
        virtual loc_t find_table_entry_for_syscall(int syscall) override;
        virtual loc_t find_function_for_syscall(int syscall) override;
        virtual loc_t find_function_for_machtrap(int trapcall) override;

        virtual loc_t find_kerneltask() override;
        virtual loc_t find_sbops() override;

        virtual loc_t find_ml_io_map() override;
        virtual loc_t find_kernel_map() override;
        virtual loc_t find_kmem_free() override;

        virtual loc_t find_bss_space(uint32_t bytecnt, bool useBytes = true) override;
        
        virtual loc_t find_pac_tag_ref(uint16_t pactag, int skip = 0, loc_t startpos = 0, int limit = 0) override;
        virtual loc_t find_boot_args_commandline_offset() override;

#pragma mark Patch finders
        virtual std::vector<patch> get_MarijuanARM_patch() override;
        virtual std::vector<patch> get_task_conversion_eval_patch() override;
        virtual std::vector<patch> get_vm_fault_internal_patch() override;

        virtual std::vector<patch> get_trustcache_true_patch() override;

        virtual std::vector<patch> get_mount_patch() override;

        virtual std::vector<patch> get_tfp0_patch() override;

        virtual std::vector<patch> get_cs_enforcement_disable_amfi_patch() override;

        virtual std::vector<patch> get_amfi_validateCodeDirectoryHashInDaemon_patch() override;

        virtual std::vector<patch> get_get_task_allow_patch() override;

        virtual std::vector<patch> get_apfs_snapshot_patch() override;

        virtual std::vector<patch> get_sandbox_patch() override;

        virtual std::vector<patch> get_nuke_sandbox_patch() override;

        virtual std::vector<patch> get_i_can_has_debugger_patch() override;

        virtual std::vector<patch> get_force_NAND_writeable_patch() override;

        virtual std::vector<patch> get_always_get_task_allow_patch() override;
        
        virtual std::vector<patch> get_allow_UID_key_patch() override;

        virtual std::vector<patch> get_ramdisk_detection_patch() override;

        /*
         Allows reading BPR status with syscall 213
         */
        
        virtual std::vector<patch> get_read_bpr_patch() override;

        
        /*
         Allows reading kerneltask_addr with syscall 213
         */
        
        virtual std::vector<patch> get_kernelbase_syscall_patch() override;
        
        virtual std::vector<patch> get_harcode_bootargs_patch(std::string bootargs) override;

        virtual std::vector<patch> get_harcode_boot_manifest_patch(const void *hash, size_t hashSize) override;

        
#pragma mark Util
        virtual loc_t find_rootvnode() override;
        virtual loc_t find_allproc() override;

#pragma mark combo utils
        virtual std::vector<patch> get_codesignature_patches() override;
        
#pragma mark non-override
        virtual std::vector<patch> get_read_bpr_patch_with_params(int syscall, loc_t bpr_reg_addr, loc_t ml_io_map, loc_t kernel_map, loc_t kmem_free);
    };
}
}

#endif /* kernelpatchfinder64_base_hpp */
