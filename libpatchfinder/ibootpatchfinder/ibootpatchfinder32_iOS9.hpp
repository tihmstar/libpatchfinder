//
//  ibootpatchfinder32_iOS9.hpp
//  libpatchfinder
//
//  Created by erd on 30.08.23.
//

#ifndef ibootpatchfinder32_iOS9_hpp
#define ibootpatchfinder32_iOS9_hpp

#include "ibootpatchfinder32_iOS5.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_iOS9 : public ibootpatchfinder32_iOS5{
        public:
            using ibootpatchfinder32_iOS5::ibootpatchfinder32_iOS5;

            /*
                disable IMG4 signature validation
             */
            virtual std::vector<patch> get_sigcheck_img4_patch() override;
        };
    };
};
#endif /* ibootpatchfinder32_iOS9_hpp */
