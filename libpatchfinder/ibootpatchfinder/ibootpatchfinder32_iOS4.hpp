//
//  ibootpatchfinder32_iOS4.hpp
//  libpatchfinder
//
//  Created by erd on 10.07.23.
//

#ifndef ibootpatchfinder32_iOS4_hpp
#define ibootpatchfinder32_iOS4_hpp

#include "ibootpatchfinder32_iOS3.hpp"


namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_iOS4 : public ibootpatchfinder32_iOS3{
        public:
            using ibootpatchfinder32_iOS3::ibootpatchfinder32_iOS3;

            /*
                disable IMG3 signature validation
             */
            virtual std::vector<patch> get_sigcheck_img3_patch() override;            
        };
    };
};
#endif /* ibootpatchfinder32_iOS4_hpp */
