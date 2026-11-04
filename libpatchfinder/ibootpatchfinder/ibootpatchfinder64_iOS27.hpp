//
//  ibootpatchfinder64_iOS27.hpp
//  libpatchfinder
//
//  Created by erd on 16.09.26.
//

#ifndef ibootpatchfinder64_iOS27_hpp
#define ibootpatchfinder64_iOS27_hpp

#include "ibootpatchfinder64_iOS26.hpp"

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_iOS27 : public ibootpatchfinder64_iOS26 {
        public:
            ibootpatchfinder64_iOS27(const char *filename);
            ibootpatchfinder64_iOS27(const void *buffer, size_t bufSize, bool takeOwnership = false);

            virtual std::vector<patch> get_force_septype_local_patch() override;
        };
    };
};
#endif /* ibootpatchfinder64_iOS27_hpp */
