//
//  kernelpatchfinder32_base.hpp
//  libpatchfinder
//
//  Created by tihmstar on 09.07.21.
//

#ifndef kernelpatchfinder32_base_hpp
#define kernelpatchfinder32_base_hpp

#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder32.hpp>

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder32_base : public kernelpatchfinder32{
        
    public:
        kernelpatchfinder32_base(const char *filename);
        kernelpatchfinder32_base(const void *buffer, size_t bufSize, bool takeOwnership = false);
        kernelpatchfinder32_base(kernelpatchfinder32 &&mv);
        virtual ~kernelpatchfinder32_base() override;
        
#pragma mark Location finders
        virtual loc64_t find_syscall0() override;
//        virtual loc_t find_machtrap_table() override;
        virtual loc64_t find_table_entry_for_syscall(int syscall) override;
        virtual loc64_t find_function_for_syscall(int syscall) override;
//        virtual loc_t find_function_for_machtrap(int trapcall) override;
        
        virtual loc64_t find_sbops() override;

#pragma mark Patch finders
        virtual std::vector<patch> get_MarijuanARM_patch() override;
        
        virtual std::vector<patch> get_trustcache_true_patch() override;
        
        virtual std::vector<patch> get_cs_enforcement_disable_amfi_patch() override;

        virtual std::vector<patch> get_amfi_validateCodeDirectoryHashInDaemon_patch() override;
        
        virtual std::vector<patch> get_mount_patch() override;
        
        virtual std::vector<patch> get_sandbox_patch() override;
        
        virtual std::vector<patch> get_allow_UID_key_patch() override;
        
        virtual std::vector<patch> get_force_NAND_writeable_patch() override;
        
        virtual std::vector<patch> get_i_can_has_debugger_patch() override;

        /*
            calls to AppleImage3NORAccessUserClient always report success to userspace, even if they failed internally
         */
        virtual std::vector<patch> get_AppleImage3NORAccess_hide_failure_patch() override;
        
        /*
         Allows reading BPR status with syscall 213
         */
        
        virtual std::vector<patch> get_read_bpr_patch() override;
        
#pragma mark Util
        virtual loc64_t find_rootvnode() override;

#pragma mark combo utils
        virtual std::vector<patch> get_codesignature_patches() override;

#pragma mark non-override
        virtual std::vector<patch> get_read_bpr_patch_with_params(int syscall, loc_t bpr_reg_addr, loc_t ml_io_map, loc_t kernel_store, loc_t kmem_free);
        
#pragma mark static
        static void slide_ptr(class patch *p, uint64_t slide);
    };
}
}
#endif /* kernelpatchfinder32_base_hpp */
