//
//  kernelpatchfinder64.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef kernelpatchfinder64_hpp
#define kernelpatchfinder64_hpp

#include <liboffsetfinder64/machopatchfinder64.hpp>

namespace tihmstar {
    namespace offsetfinder64 {
        class kernelpatchfinder64 : public machopatchfinder64{
            std::vector<std::pair<loc_t, loc_t>> _usedNops;
            
        public:
            kernelpatchfinder64(const char *filename);
            kernelpatchfinder64(const void *buffer, size_t bufSize);
            
            loc_t findnops(uint16_t nopCnt, bool useNops = true);
            
            loc_t find_syscall0();
            loc_t find_machtrap_table();
            loc_t find_function_for_syscall(int syscall);
            loc_t find_function_for_machtrap(int trapcall);

            loc_t find_kerneltask();

            std::vector<patch> get_MarijuanARM_patch();            
            std::vector<patch> get_task_conversion_eval_patch();
            std::vector<patch> get_vm_fault_internal_patch();

            std::vector<patch> get_trustcache_true_patch();

            std::vector<patch> get_mount_patch();

            std::vector<patch> get_tfp0_patch();

            std::vector<patch> get_amfi_patch(bool doApplyPatch = true); //don't use up nop space by multiple patches if this is set to true

            std::vector<patch> get_get_task_allow_patch();

            std::vector<patch> get_apfs_snapshot_patch();

            /*------------------------ Util -------------------------- */
            offsetfinder64::loc_t find_rootvnode();
            offsetfinder64::loc_t find_allproc();
        };
    };
};

#endif /* kernelpatchfinder64_hpp */
