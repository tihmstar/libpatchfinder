//
//  ibootpatchfinder64_iOS14.hpp
//  libpatchfinder
//
//  Created by tihmstar on 28.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_iOS14_hpp
#define ibootpatchfinder64_iOS14_hpp

#include "ibootpatchfinder64_iOS13.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS14 : public ibootpatchfinder64_iOS13{
        public:
            ibootpatchfinder64_iOS14(const char *filename);
            ibootpatchfinder64_iOS14(const void *buffer, size_t bufSize, bool takeOwnership = false);

            
            virtual std::vector<patch> get_sigcheck_img4_patch() override;

            virtual std::vector<patch> get_change_reboot_to_fsboot_patch() override;
            
            virtual std::vector<patch> get_boot_arg_patch(const char *bootargs) override;
            
            virtual std::vector<patch> get_force_septype_local_patch() override;
            
            /*
                Skip setting BPR by iBoot
             */
            virtual std::vector<patch> get_skip_set_bpr_patch() override;
            
            /*
                Always set "sepfw-booted" in devicetree
             */
            virtual std::vector<patch> get_always_sepfw_booted_patch() override;
            
            virtual std::vector<patch> get_tz0_lock_patch() override;
        };
    };
};

#endif /* ibootpatchfinder64_iOS14_hpp */
