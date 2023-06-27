//
//  ibootpatchfinder64_iOS16.hpp
//  libpatchfinder
//
//  Created by tihmstar on 08.06.22.
//

#ifndef ibootpatchfinder64_iOS16_hpp
#define ibootpatchfinder64_iOS16_hpp

#include "ibootpatchfinder64_iOS15.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS16 : public ibootpatchfinder64_iOS15{
        public:
            using ibootpatchfinder64_iOS15::ibootpatchfinder64_iOS15;
            
            virtual std::vector<patch> get_skip_set_bpr_patch() override;
            
            /*
                Ignore force_dfu in iBoot
             */
            virtual std::vector<patch> get_no_force_dfu_patch() override;
        };
    };
};
#endif /* ibootpatchfinder64_iOS16_hpp */
