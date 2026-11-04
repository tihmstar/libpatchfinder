//
//  ibootpatchfinder64_iOS18.hpp
//  libpatchfinder
//
//  Created by erd on 15.07.26.
//

#ifndef ibootpatchfinder64_iOS18_hpp
#define ibootpatchfinder64_iOS18_hpp

#include "ibootpatchfinder64_iOS17.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS18 : public ibootpatchfinder64_iOS17{
        public:
            using ibootpatchfinder64_iOS17::ibootpatchfinder64_iOS17;
            
            /*
               make an iBoot command jump to a specific address
             */
            virtual std::vector<patch> get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr) override;            
        };
    };
};
#endif /* ibootpatchfinder64_iOS18_hpp */
