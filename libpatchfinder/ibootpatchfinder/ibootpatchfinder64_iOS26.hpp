//
//  ibootpatchfinder64_iOS26.hpp
//  libpatchfinder
//
//  Created by erd on 05.11.25.
//

#ifndef ibootpatchfinder64_iOS26_hpp
#define ibootpatchfinder64_iOS26_hpp

#include "ibootpatchfinder64_iOS18.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS26 : public ibootpatchfinder64_iOS18 {
        public:
            using ibootpatchfinder64_iOS18::ibootpatchfinder64_iOS18;
            
            virtual std::vector<patch> get_force_septype_local_patch() override;
        };
    };
};
#endif /* ibootpatchfinder64_iOS26_hpp */
