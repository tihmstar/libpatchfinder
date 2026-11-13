//
//  ibootpatchfinder32_iOS8.hpp
//  libpatchfinder
//
//  Created by erd on 16.10.23.
//

#ifndef ibootpatchfinder32_iOS8_hpp
#define ibootpatchfinder32_iOS8_hpp

#include "ibootpatchfinder32_iOS5.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_iOS8 : public ibootpatchfinder32_iOS5{
        public:
            using ibootpatchfinder32_iOS5::ibootpatchfinder32_iOS5;
            
            virtual std::vector<patch> get_honor_nvram_boot_arg_patch() override;
        };
    };
};
#endif /* ibootpatchfinder32_iOS8_hpp */
