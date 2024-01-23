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
            
            /*
                set root-ticket-hash
             */
            virtual std::vector<patch> set_root_ticket_hash(const void *hash, size_t hashSize) override;

        };
    };
};
#endif /* ibootpatchfinder32_iOS8_hpp */
