//
//  ibootpatchfinder32_iOS11.hpp
//  libpatchfinder
//
//  Created by tihmstar on 11.12.21.
//

#ifndef ibootpatchfinder32_iOS11_hpp
#define ibootpatchfinder32_iOS11_hpp

#include "ibootpatchfinder32_iOS5.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_iOS11 : public ibootpatchfinder32_iOS5{
        public:
            using ibootpatchfinder32_iOS5::ibootpatchfinder32_iOS5;

            /*
                Skip setting BPR by iBoot
             */
            virtual std::vector<patch> get_skip_set_bpr_patch() override;            
        };
    };
};

#endif /* ibootpatchfinder32_iOS11_hpp */
