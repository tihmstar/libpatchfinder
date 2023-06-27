//
//  offsetfinder64.hpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef patchfinder64_hpp
#define patchfinder64_hpp

#include <string>
#include <vector>
#include <functional>
#include <map>

#include <stdint.h>
#include <stdlib.h>

#include <libinsn/vmem.hpp>

#include <libpatchfinder/OFexception.hpp>
#include <libpatchfinder/patch.hpp>

namespace tihmstar {
    namespace patchfinder{
        class patchfinder64 {
        public:
            using vmem = tihmstar::libinsn::vmem<tihmstar::libinsn::arm64::insn>;
            using vsegment = tihmstar::libinsn::vsegment;
            using loc_t = tihmstar::libinsn::arm64::insn::loc_t;
            using offset_t = tihmstar::libinsn::arm64::insn::offset_t;
        protected:
            bool _freeBuf;
            const uint8_t *_buf;
            size_t _bufSize;
            loc_t _entrypoint;
            loc_t _base;
            const tihmstar::libinsn::vmem<libinsn::arm64::insn> *_vmem;
            std::vector<std::pair<loc_t, size_t>> _unusedNops;
            std::map<std::string,std::vector<patch>> _savedPatches;

            
        public:
            patchfinder64(bool freeBuf);
            patchfinder64(const patchfinder64 &cpy) = delete;
            patchfinder64(patchfinder64 &&mv);
            
            ~patchfinder64();
            
            const void *buf() { return _buf;}
            size_t bufSize() { return _bufSize;}
            loc_t find_entry() { return _entrypoint;}
            loc_t find_base() { return _base; }
            
            const void *memoryForLoc(loc_t loc);

            
            loc_t findstr(std::string str, bool hasNullTerminator, loc_t startAddr = 0);
            loc_t find_bof(loc_t pos, bool mayLackPrologue = false);
            uint64_t find_register_value(loc_t where, int reg, loc_t startAddr = 0);
            loc_t find_literal_ref(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            loc_t find_call_ref(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            loc_t find_branch_ref(loc_t pos, int limit, int ignoreTimes = 0, loc_t startPos = 0);
            loc_t findnops(uint16_t nopCnt, bool useNops = true, uint32_t nopOpcode = 0xd503201f /*nop insn*/);

            
            uint32_t pageshit_for_pagesize(uint32_t pagesize);
            uint64_t pte_vma_to_index(uint32_t pagesize, uint8_t level, uint64_t address);
            uint64_t pte_index_to_vma(uint32_t pagesize, uint8_t level, uint64_t index);

            
            /*
                Patch replace strings (or raw bytes).
             */
            std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement);
        };
        
    };
}


#endif /* patchfinder64_hpp */
