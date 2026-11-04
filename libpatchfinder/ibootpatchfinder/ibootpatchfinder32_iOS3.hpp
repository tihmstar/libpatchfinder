//
//  ibootpatchfinder32_iOS3.hpp
//  libpatchfinder
//
//  Created by erd on 16.09.24.
//

#ifndef ibootpatchfinder32_iOS3_hpp
#define ibootpatchfinder32_iOS3_hpp

#include "ibootpatchfinder32_base.hpp"


namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_iOS3 : public ibootpatchfinder32_base{
        public:
            using ibootpatchfinder32_base::ibootpatchfinder32_base;

            /*
               make kernel boot with these bootargs
             */
            virtual std::vector<patch> get_boot_arg_patch(const char *bootargs) override;

            virtual std::vector<patch> get_honor_nvram_boot_arg_patch() override;
            
            /*
                Don't make iBoot print a list of all bdev images
             */
            virtual std::vector<patch> get_no_img3_dumplist_patch() override;
        };
    };
};
#endif /* ibootpatchfinder32_iOS3_hpp */
