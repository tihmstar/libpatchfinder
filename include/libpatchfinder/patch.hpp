//
//  patch.hpp
//  libpatchfinder
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef patch_hpp
#define patch_hpp

#include <stdlib.h>
#include <stdint.h>

namespace tihmstar {
    namespace patchfinder{
        class patch{
            bool _slideme;
            bool _dofree;
            void(*_slidefunc)(class patch *patch, uint64_t slide);
        public:
            uint64_t _location;
            size_t _patchSize;
            const void *_patch;
            patch(uint64_t location, const void *patch, size_t patchSize, void(*slidefunc)(class patch *patch, uint64_t slide) = NULL, bool dofree = true);
            patch(const patch& cpy) noexcept;
            ~patch();

            patch &operator=(const patch& cpy);
            void slide(uint64_t slide);
        };

    }
}

#endif /* patch_hpp */
