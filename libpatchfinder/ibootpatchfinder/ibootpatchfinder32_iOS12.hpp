//
//  ibootpatchfinder32_iOS12.hpp
//  libpatchfinder
//
//  Created by tihmstar on 21.12.21.
//

#ifndef ibootpatchfinder32_iOS12_hpp
#define ibootpatchfinder32_iOS12_hpp

#include "ibootpatchfinder32_iOS11.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_iOS12 : public ibootpatchfinder32_iOS11{
        public:
            using ibootpatchfinder32_iOS11::ibootpatchfinder32_iOS11;

            virtual std::vector<patch> get_force_septype_local_patch() override;
        };
    };
};
#endif /* ibootpatchfinder32_iOS12_hpp */
