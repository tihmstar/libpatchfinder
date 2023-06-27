//
//  ibootpatchfinder64_iOS17.hpp
//  libpatchfinder
//
//  Created by erd on 21.06.23.
//

#ifndef ibootpatchfinder64_iOS17_hpp
#define ibootpatchfinder64_iOS17_hpp

#include "ibootpatchfinder64_iOS16.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS17 : public ibootpatchfinder64_iOS16{
        public:
            using ibootpatchfinder64_iOS16::ibootpatchfinder64_iOS16;
            
            virtual std::vector<patch> get_force_septype_local_patch() override;
        };
    };
};
#endif /* ibootpatchfinder64_iOS17_hpp */
