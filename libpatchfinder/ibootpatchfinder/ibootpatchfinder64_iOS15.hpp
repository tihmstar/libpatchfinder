//
//  ibootpatchfinder64_iOS15.hpp
//  libpatchfinder
//
//  Created by tihmstar on 01.10.21.
//

#ifndef ibootpatchfinder64_iOS15_hpp
#define ibootpatchfinder64_iOS15_hpp

#include "ibootpatchfinder64_iOS14.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS15 : public ibootpatchfinder64_iOS14{
        public:
            using ibootpatchfinder64_iOS14::ibootpatchfinder64_iOS14;
                                                
            virtual std::vector<patch> get_sigcheck_img4_patch() override;
            
            /*
                Make iBoot think we're in production mode, even if we demoted
             */
            virtual std::vector<patch> get_always_production_patch() override;
        };
    };
};
#endif /* ibootpatchfinder64_iOS15_hpp */
