//
//  ibootpatchfinder32_iOS5.hpp
//  libpatchfinder
//
//  Created by Elcomsoft R&D on 10.01.23.
//

#ifndef ibootpatchfinder32_iOS5_hpp
#define ibootpatchfinder32_iOS5_hpp

#include "ibootpatchfinder32_iOS4.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_iOS5 : public ibootpatchfinder32_iOS4{
        public:
            using ibootpatchfinder32_iOS4::ibootpatchfinder32_iOS4;

            /*
                disable IMG3 signature validation
             */
            virtual std::vector<patch> get_sigcheck_img3_patch() override;
            
            
            /*
                set root-ticket-hash
             */
            virtual std::vector<patch> set_root_ticket_hash(std::vector<uint8_t> hash) override;

        };
    };
};
#endif /* ibootpatchfinder32_iOS5_hpp */
