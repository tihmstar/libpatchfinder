//
//  ibootpatchfinder32_iOS13.hpp
//  libpatchfinder
//
//  Created by tihmstar on 20.07.21.
//

#ifndef ibootpatchfinder32_iOS13_hpp
#define ibootpatchfinder32_iOS13_hpp

#include "ibootpatchfinder32_iOS12.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_iOS13 : public ibootpatchfinder32_iOS12{
        public:
            using ibootpatchfinder32_iOS12::ibootpatchfinder32_iOS12;

            virtual std::vector<patch> get_boot_arg_patch(const char *bootargs) override;
            
            virtual std::vector<patch> get_force_septype_local_patch() override;
        };
    };
};
#endif /* ibootpatchfinder32_iOS13_hpp */
