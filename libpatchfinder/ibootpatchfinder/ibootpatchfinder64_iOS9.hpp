//
//  ibootpatchfinder64_iOS9.hpp
//  libpatchfinder
//
//  Created by tihmstar on 15.02.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_iOS9_hpp
#define ibootpatchfinder64_iOS9_hpp

#include "ibootpatchfinder64_iOS7.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS9 : public ibootpatchfinder64_iOS7{
        public:
            using ibootpatchfinder64_iOS7::ibootpatchfinder64_iOS7;
            
            virtual std::vector<patch> get_sigcheck_img4_patch() override;
            
            virtual loc_t find_iBoot_logstr(uint64_t loghex, int skip = 0, uint64_t shortdec = 0) override;
        };
    };
};

#endif /* ibootpatchfinder64_iOS9_hpp */
