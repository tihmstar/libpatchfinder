//
//  txmpatchfinder.hpp
//  libpatchfinder
//
//  Created by erd on 13.10.26.
//

#ifndef txmpatchfinder_hpp
#define txmpatchfinder_hpp

#include <libinsn/vmem.hpp>
#include <libpatchfinder/patch.hpp>
#include <libpatchfinder/patchfinder.hpp>

#include <libgeneral/Mem.hpp>

namespace tihmstar {
    namespace patchfinder {
        class txmpatchfinder{
        public:
            using loc64_t = tihmstar::libinsn::arm64::insn::loc_t;
            using offset_t = tihmstar::libinsn::arm64::insn::offset_t;
        public:
            virtual ~txmpatchfinder();
            
            virtual const void *memoryForLoc(loc64_t loc);
            /*
                Patch replace strings (or raw bytes).
             */
            virtual std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement);

            
            /*
                Provides a set patches to disable codesignature checks
             */
            virtual std::vector<patch> get_codesignature_patches();
        };
    };
};
#endif /* txmpatchfinder_hpp */
