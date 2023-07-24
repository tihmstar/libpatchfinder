//
//  kernelpatchfinder64_iOS16.hpp
//  libpatchfinder
//
//  Created by tihmstar on 08.06.22.
//

#ifndef kernelpatchfinder64_iOS16_hpp
#define kernelpatchfinder64_iOS16_hpp

#include "kernelpatchfinder64_iOS15.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS16 : public kernelpatchfinder64_iOS15{
    public:
        using kernelpatchfinder64_iOS15::kernelpatchfinder64_iOS15;
                
#pragma mark Location finders
        virtual loc_t find_boot_args_commandline_offset() override;
        virtual loc_t find_sbops() override;

#pragma mark Patch finders
        virtual std::vector<patch> get_trustcache_true_patch() override;
        
        virtual std::vector<patch> get_codesignature_patches() override;
        
        virtual std::vector<patch> get_force_boot_ramdisk_patch() override;
        
        virtual std::vector<patch> get_read_bpr_patch_with_params(int syscall, loc_t bpr_reg_addr, loc_t ml_io_map, loc_t kernel_map, loc_t kmem_free) override;
        
        virtual std::vector<patch> get_mount_patch() override;
        
        virtual std::vector<patch> get_apfs_skip_authenticate_root_hash_patch() override;
                
        virtual std::vector<patch> get_sandbox_patch() override;
        
        virtual std::vector<patch> get_task_conversion_eval_patch() override;
    };
}
}
#endif /* kernelpatchfinder64_iOS16_hpp */
