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

#include <libpatchfinder/patchfinder.hpp>
#include <libinsn/vmem.hpp>

namespace tihmstar {
    namespace patchfinder{
        class patchfinder64 : public patchfinder {
        public:
            using vmem = tihmstar::libinsn::vmem<tihmstar::libinsn::arm64::insn>;
            using vsegment = tihmstar::libinsn::vsegment;
            using loc_t = tihmstar::libinsn::arm64::insn::loc_t;
            using offset_t = tihmstar::libinsn::arm64::insn::offset_t;
        protected:
            const tihmstar::libinsn::vmem<libinsn::arm64::insn> *_vmem;
            std::vector<std::pair<loc_t, size_t>> _unusedNops;
            std::map<std::string,std::vector<patch>> _savedPatches;

        public:
            patchfinder64(bool freeBuf);
            patchfinder64(const patchfinder64 &cpy) = delete;
            patchfinder64(patchfinder64 &&mv);
            
            patchfinder64(loc_t base, const char *filename, std::vector<psegment> segments = {});
            patchfinder64(loc_t base, const void *buffer, size_t bufSize, bool takeOwnership = false, std::vector<psegment> segments = {});

            virtual ~patchfinder64();
                        
#pragma mark provider for parent
            virtual const void *memoryForLoc(loc_t loc) override;
            virtual loc_t findstr(std::string str, bool hasNullTerminator, loc_t startAddr = 0) override;
            virtual loc_t find_bof(loc_t pos, bool mayLackPrologue = false) override;
            virtual uint64_t find_register_value(loc_t where, int reg, loc_t startAddr = 0) override;
            virtual loc_t find_literal_ref(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0) override;
            virtual loc_t find_call_ref(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0) override;
            virtual loc_t find_branch_ref(loc_t pos, int limit, int ignoreTimes = 0, loc_t startPos = 0) override;
            virtual loc_t findnops(uint16_t nopCnt, bool useNops = true, uint32_t nopOpcode = 0xd503201f /*nop insn*/) override;
            virtual loc_t memmem(const void *little, size_t little_len, patchfinder::loc_t startLoc = 0) const override;
            virtual loc_t memstr(const char *str) const override;
            virtual loc_t deref(loc_t pos) const override;
            
#pragma mark own functions
            uint32_t pageshit_for_pagesize(uint32_t pagesize);
            uint64_t pte_vma_to_index(uint32_t pagesize, uint8_t level, uint64_t address);
            uint64_t pte_index_to_vma(uint32_t pagesize, uint8_t level, uint64_t index);

#pragma mark own functions virtual
            virtual uint16_t getPointerAuthStringDiscriminator(const char *strDesc);
            virtual loc_t find_PACedPtrRefWithStrDesc(const char *strDesc, int ignoreTimes = 0, loc_t startPos = 0);
        };        
    };
}


#endif /* patchfinder64_hpp */
