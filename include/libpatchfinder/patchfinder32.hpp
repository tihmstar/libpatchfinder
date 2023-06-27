//
//  patchfinder32.hpp
//  patchfinder
//
//  Created by tihmstar on 06.07.21.
//

#ifndef patchfinder32_hpp
#define patchfinder32_hpp

#include <string>
#include <vector>
#include <functional>

#include <stdint.h>
#include <stdlib.h>

#include <libinsn/vmem.hpp>

#include <libpatchfinder/OFexception.hpp>
#include <libpatchfinder/patch.hpp>

namespace tihmstar {
    namespace patchfinder{
        class patchfinder32 {
        public:
            using vmem_thumb = tihmstar::libinsn::vmem<tihmstar::libinsn::arm32::thumb>;
            using vmem_arm = tihmstar::libinsn::vmem<tihmstar::libinsn::arm32::arm>;
            using vsegment = tihmstar::libinsn::vsegment;

            using loc_t = tihmstar::libinsn::arm32::thumb::loc_t;
            using offset_t = tihmstar::libinsn::arm32::thumb::offset_t;
        protected:
            bool _freeBuf;
            const uint8_t *_buf;
            size_t _bufSize;
            loc_t _entrypoint;
            loc_t _base;
            const tihmstar::libinsn::vmem<libinsn::arm32::thumb> *_vmem;
            std::vector<std::pair<loc_t, loc_t>> _usedNops;

            
        public:
            patchfinder32(bool freeBuf);
            patchfinder32(const patchfinder32 &cpy) = delete;
            patchfinder32(patchfinder32 &&mv);
            
            ~patchfinder32();
            
            const void *buf() { return _buf;}
            size_t bufSize() { return _bufSize;}
            loc_t find_entry() { return _entrypoint;}
            loc_t find_base() { return _base; }
            
            const void *memoryForLoc(loc_t loc);

            
            loc_t findstr(std::string str, bool hasNullTerminator, loc_t startAddr = 0);
            loc_t find_bof_thumb(loc_t pos);
//            uint64_t find_register_value(loc_t where, int reg, loc_t startAddr = 0);
            loc_t find_literal_ref_thumb(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            loc_t find_call_ref_thumb(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            loc_t find_branch_ref_thumb(loc_t pos, int limit, int ignoreTimes = 0);
            loc_t findnops(uint16_t nopCnt, bool useNops = true, uint32_t nopOpcode = 0xE1A00000 /*nop insn*/);
                        
            /*
                Patch replace strings (or raw bytes).
             */
            std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement);
        };
        
    };
}


#endif /* patchfinder32_hpp */
