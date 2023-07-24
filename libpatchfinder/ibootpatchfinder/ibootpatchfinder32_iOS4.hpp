//
//  ibootpatchfinder32_iOS4.hpp
//  libpatchfinder
//
//  Created by erd on 10.07.23.
//

#ifndef ibootpatchfinder32_iOS4_hpp
#define ibootpatchfinder32_iOS4_hpp

#include "ibootpatchfinder32_base.hpp"


namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_iOS4 : public ibootpatchfinder32_base{
        public:
            using ibootpatchfinder32_base::ibootpatchfinder32_base;

            /*
                disable IMG3 signature validation
             */
            virtual std::vector<patch> get_sigcheck_img3_patch() override;            
        };
    };
};
#endif /* ibootpatchfinder32_iOS4_hpp */
