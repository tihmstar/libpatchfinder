//
//  offsetfinder64.hpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef offsetfinder64_hpp
#define offsetfinder64_hpp

#include <string>
#include <vector>
#include <functional>

#include <stdint.h>
#include <stdlib.h>

#include <libinsn/vmem.hpp>

#include <liboffsetfinder64/common.h>
#include <liboffsetfinder64/OFexception.hpp>
#include <liboffsetfinder64/patch.hpp>

namespace tihmstar {
    namespace offsetfinder64{
        
        class patchfinder64 {
        protected:
            bool _freeBuf;
            const uint8_t *_buf;
            size_t _bufSize;
            offsetfinder64::loc_t _entrypoint;
            offsetfinder64::loc_t _base;
            tihmstar::libinsn::vmem *_vmem;
            std::vector<std::pair<loc_t, loc_t>> _usedNops;

            
        public:
            patchfinder64(bool freeBuf);
            ~patchfinder64();
            
            const void *buf() { return _buf;}
            size_t bufSize() { return _bufSize;}
            loc_t find_entry() { return _entrypoint;}
            loc_t find_base() { return _base; }
            
            const void *memoryForLoc(loc_t loc);

            
            loc_t findstr(std::string str, bool hasNullTerminator, loc_t startAddr = 0);
            loc_t find_bof(loc_t pos);
            uint64_t find_register_value(loc_t where, int reg, loc_t startAddr = 0);
            loc_t find_literal_ref(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            loc_t find_call_ref(loc_t pos, int ignoreTimes = 0);
            loc_t find_branch_ref(loc_t pos, int limit, int ignoreTimes = 0);
            loc_t findnops(uint16_t nopCnt, bool useNops = true);

            
            uint32_t pageshit_for_pagesize(uint32_t pagesize);
            uint64_t pte_vma_to_index(uint32_t pagesize, uint8_t level, uint64_t address);
            uint64_t pte_index_to_vma(uint32_t pagesize, uint8_t level, uint64_t index);

        };
        
    };
}


#endif /* offsetfinder64_hpp */
