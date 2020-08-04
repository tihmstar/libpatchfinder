//
//  ibootpatchfinder64_iOS14.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_iOS14_hpp
#define ibootpatchfinder64_iOS14_hpp

#include <liboffsetfinder64/ibootpatchfinder64_base.hpp>

namespace tihmstar {
    namespace offsetfinder64 {
        class ibootpatchfinder64_iOS14 : public ibootpatchfinder64_base{
        public:
            ibootpatchfinder64_iOS14(const char *filename);
            ibootpatchfinder64_iOS14(const void *buffer, size_t bufSize, bool takeOwnership = false);

            
            virtual std::vector<patch> get_sigcheck_patch() override;

            virtual std::vector<patch> get_change_reboot_to_fsboot_patch() override;

            virtual loc_t find_iBoot_logstr(uint64_t loghex, int skip = 0, uint64_t shortdec = 0) override;

        };
    };
};

#endif /* ibootpatchfinder64_iOS14_hpp */
