//
//  ibootpatchfinder64_iOS12.hpp
//  libpatchfinder
//
//  Created by tihmstar on 22.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_iOS12_hpp
#define ibootpatchfinder64_iOS12_hpp

#include "ibootpatchfinder64_iOS11.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS12 : public ibootpatchfinder64_iOS11{
        public:
            using ibootpatchfinder64_iOS11::ibootpatchfinder64_iOS11;
            
            virtual std::vector<patch> get_force_septype_local_patch() override;            
        };
    };
};
#endif /* ibootpatchfinder64_iOS12_hpp */
