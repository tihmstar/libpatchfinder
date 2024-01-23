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

#include <libpatchfinder/patchfinder.hpp>

namespace tihmstar {
    namespace patchfinder{
        class patchfinder32 : public patchfinder {
        public:
            using vmem_thumb = tihmstar::libinsn::vmem<tihmstar::libinsn::arm32::thumb>;
            using vmem_arm = tihmstar::libinsn::vmem<tihmstar::libinsn::arm32::arm>;
            using vsegment = tihmstar::libinsn::vsegment;
            using loc_t = tihmstar::libinsn::arm32::thumb::loc_t;
        protected:
            const vmem_thumb *_vmemThumb;
            const vmem_arm *_vmemArm;
            std::vector<std::pair<loc_t, loc_t>> _usedNops;
            std::map<std::string,std::vector<patch>> _savedPatches;

        public:
            patchfinder32(bool freeBuf);
            patchfinder32(const patchfinder32 &cpy) = delete;
            patchfinder32(patchfinder32 &&mv);
            
            patchfinder32(loc_t base, const char *filename, std::vector<psegment> segments = {});
            patchfinder32(loc_t base, const void *buffer, size_t bufSize, bool takeOwnership = false, std::vector<psegment> segments = {});

            ~patchfinder32();
            
#pragma mark provider for parent
            virtual const void *memoryForLoc(patchfinder::loc_t loc) override;
            virtual patchfinder::loc_t findstr(std::string str, bool hasNullTerminator, patchfinder::loc_t startAddr = 0) override;
            virtual patchfinder::loc_t find_bof(patchfinder::loc_t pos, bool mayLackPrologue = false) override;
            virtual uint64_t find_register_value(patchfinder::loc_t where, int reg, patchfinder::loc_t startAddr = 0) override;
            virtual patchfinder::loc_t find_literal_ref(patchfinder::loc_t pos, int ignoreTimes = 0, patchfinder::loc_t startPos = 0) override;
            virtual patchfinder::loc_t find_call_ref(patchfinder::loc_t pos, int ignoreTimes = 0, patchfinder::loc_t startPos = 0) override;
            virtual patchfinder::loc_t find_branch_ref(patchfinder::loc_t pos, int limit, int ignoreTimes = 0, patchfinder::loc_t startPos = 0) override;
            virtual patchfinder::loc_t findnops(uint16_t nopCnt, bool useNops = true, uint32_t nopOpcode = 0xd503201f /*nop insn*/) override;
            virtual patchfinder::loc_t memmem(const void *little, size_t little_len, patchfinder::loc_t startLoc = 0) const override;
            virtual patchfinder::loc_t memstr(const char *str) const override;
            virtual patchfinder::loc_t deref(patchfinder::loc_t pos) const override;

#pragma mark own functions
            loc_t find_bof_thumb(loc_t pos);
            loc_t find_bof_arm(loc_t pos);
            uint32_t find_register_value_thumb(loc_t where, uint8_t reg, loc_t startAddr = 0);
            loc_t find_literal_ref_arm(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            loc_t find_literal_ref_thumb(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            loc_t find_call_ref_thumb(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            loc_t find_branch_ref_thumb(loc_t pos, int limit, int ignoreTimes = 0, loc_t startPos = 0);
        };
        
    };
}


#endif /* patchfinder32_hpp */
