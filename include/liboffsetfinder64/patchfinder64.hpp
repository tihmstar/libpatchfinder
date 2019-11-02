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
#include <stdint.h>
#include <vector>
#include <functional>

#include <stdlib.h>
#include <liboffsetfinder64/common.h>
#include <liboffsetfinder64/insn.hpp>
#include <liboffsetfinder64/OFexception.hpp>
#include <liboffsetfinder64/patch.hpp>
#include <liboffsetfinder64/vmem.hpp>
#include <functional>

namespace tihmstar {
    namespace offsetfinder64{
        
        class patchfinder64 {
        protected:
            bool _freeBuf;
            const uint8_t *_buf;
            size_t _bufSize;
            offsetfinder64::loc_t _entrypoint;
            offsetfinder64::loc_t _base;
            offsetfinder64::vmem *_vmem;
            
        public:
            patchfinder64(bool freeBuf);
            ~patchfinder64();
            
            const void *buf() { return _buf;}
            size_t bufSize() { return _bufSize;}
            loc_t find_entry() { return _entrypoint;}
            loc_t find_base() { return _base; }
            
            loc_t findstr(std::string str, bool hasNullTerminator);
            loc_t find_bof(loc_t pos);
            uint64_t find_register_value(loc_t where, int reg, loc_t startAddr = 0);
            loc_t find_literal_ref(loc_t pos, int ignoreTimes = 0);
            loc_t find_branch_ref(loc_t pos, int ignoreTimes = 0);
            
        };
        
    };
}


#endif /* offsetfinder64_hpp */
