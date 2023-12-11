//
//  ibootpatchfinder64_iOS7.hpp
//  libpatchfinder
//
//  Created by tihmstar on 07.04.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_iOS7_hpp
#define ibootpatchfinder64_iOS7_hpp

#include "ibootpatchfinder64_base.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS7 : public ibootpatchfinder64_base{
        public:
            using ibootpatchfinder64_base::ibootpatchfinder64_base;
            
            virtual std::vector<patch> get_sigcheck_img4_patch() override;
        };
    };
};
#endif /* ibootpatchfinder64_iOS7_hpp */
