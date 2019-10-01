//
//  machopatchfinder64.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef machopatchfinder64_hpp
#define machopatchfinder64_hpp

#include <liboffsetfinder64/patchfinder64.hpp>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>

namespace tihmstar {
    namespace offsetfinder64 {
        
        class machopatchfinder64 : public patchfinder64{
            struct symtab_command *__symtab;
            
            void loadSegments();
            __attribute__((always_inline)) struct symtab_command *getSymtab();
            
        public:
            machopatchfinder64(const char *filename);
            
            bool haveSymbols() { return __symtab != NULL;};
            loc_t find_sym(const char *sym);

        };
        
    };
};


#endif /* machopatchfinder64_hpp */
