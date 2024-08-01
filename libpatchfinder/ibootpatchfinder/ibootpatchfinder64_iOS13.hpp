//
//  ibootpatchfinder64_iOS13.hpp
//  libpatchfinder
//
//  Created by tihmstar on 13.01.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_iOS13_hpp
#define ibootpatchfinder64_iOS13_hpp

#include "ibootpatchfinder64_iOS12.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS13 : public ibootpatchfinder64_iOS12{
        public:
            using ibootpatchfinder64_iOS12::ibootpatchfinder64_iOS12;
                    
            virtual std::vector<patch> get_force_septype_local_patch() override;

            /*
             replace command with: "memcpy <dst> <src> <size>"
             */
            virtual std::vector<patch> replace_cmd_with_memcpy(const char *cmd_handler_str) override;

            /*
                Make iBoot think we're in production mode, even if we demoted
             */
            virtual std::vector<patch> get_always_production_patch() override;
            
            virtual uint32_t get_el1_pagesize() override;

            virtual std::vector<patch> get_rw_and_x_mappings_patch_el1() override;
            
            virtual std::vector<patch> get_ra1nra1n_patch() override;
        };
    };
};
#endif /* ibootpatchfinder64_iOS13_hpp */
