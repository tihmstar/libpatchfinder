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
            void *_patch;
            size_t _patchSize;
            bool _slideme;
            void(*_slidefunc)(class patch *patch, uint64_t slide);
        public:
            uint64_t _location;
            patch(uint64_t location, const void *patch, size_t patchSize, void(*slidefunc)(class patch *patch, uint64_t slide) = NULL);
            patch(const patch& cpy) noexcept;
            ~patch();
            
            inline const void *getPatch(){return _patch;}
            inline size_t getPatchSize(){return  _patchSize;}
            
            patch &operator=(const patch& cpy);
            void slide(uint64_t slide);
        };

    }
}

#endif /* patch_hpp */
