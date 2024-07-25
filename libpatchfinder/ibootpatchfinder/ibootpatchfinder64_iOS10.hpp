//
//  ibootpatchfinder64_iOS10.hpp
//  libpatchfinder
//
//  Created by tihmstar on 26.02.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_iOS10_hpp
#define ibootpatchfinder64_iOS10_hpp

#include "ibootpatchfinder64_iOS9.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS10 : public ibootpatchfinder64_iOS9{
        public:
            using ibootpatchfinder64_iOS9::ibootpatchfinder64_iOS9;
            
            /*
                Skip setting BPR by iBoot
             */
            virtual std::vector<patch> get_skip_set_bpr_patch() override;
            
            virtual std::vector<patch> get_sigcheck_img4_patch() override;
        };
    };
};
#endif /* ibootpatchfinder64_iOS10_hpp */
