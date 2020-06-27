//
//  patch.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef patch_hpp
#define patch_hpp

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <liboffsetfinder64/common.h>

namespace tihmstar {
    namespace offsetfinder64{
        class patch{
            bool _slideme;
            void(*_slidefunc)(class patch *patch, uint64_t slide);
        public:
            loc_t _location;
            size_t _patchSize;
            const void *_patch;
            patch(loc_t location, const void *patch, size_t patchSize, void(*slidefunc)(class patch *patch, uint64_t slide) = NULL);
            patch(const patch& cpy) noexcept;
            patch &operator=(const patch& cpy);
            void slide(uint64_t slide);
            ~patch();
        };

    }
}

#endif /* patch_hpp */
