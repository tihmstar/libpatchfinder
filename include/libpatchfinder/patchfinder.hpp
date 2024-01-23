//
//  patchfinder.hpp
//  libpatchfinder
//
//  Created by erd on 29.06.23.
//

#ifndef patchfinder_hpp
#define patchfinder_hpp

#include <stdint.h>
#include <stdlib.h>
#include <vector>

#include <libinsn/vmem.hpp>

#include <libpatchfinder/OFexception.hpp>
#include <libpatchfinder/patch.hpp>

namespace tihmstar {
    namespace patchfinder{
        class patchfinder {
        public:
            enum pprot{
                kPPROTALL   = 0,
                kPPROTREAD  = 1 << 0,
                kPPROTWRITE = 1 << 1,
                kPPROTEXEC  = 1 << 2,
            };
            struct psegment{
                size_t fileOffset;
                size_t size;
                uint64_t vaddr;
                pprot perms;
            };
            using loc_t = tihmstar::libinsn::arm64::insn::loc_t;

        protected:
            bool _freeBuf;
            const uint8_t *_buf;
            size_t _bufSize;
            loc_t _entrypoint;
            loc_t _base;
        public:
            patchfinder(bool freeBuf);
            patchfinder(const patchfinder &cpy) = delete;
            patchfinder(patchfinder &&mv);
            
            virtual ~patchfinder();

            const void *buf();
            size_t bufSize();
            loc_t find_entry();
            loc_t find_base();
            
#pragma mark no-provider
            virtual const void *memoryForLoc(loc_t loc);
            virtual loc_t findstr(std::string str, bool hasNullTerminator, loc_t startAddr = 0);
            virtual loc_t find_bof(loc_t pos, bool mayLackPrologue = false);
            virtual loc_t find_bof_with_sting_ref(const char *str, bool hasNullTerminator);
            virtual loc_t find_literal_ref(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            virtual loc_t find_call_ref(loc_t pos, int ignoreTimes = 0, loc_t startPos = 0);
            virtual loc_t find_branch_ref(loc_t pos, int limit, int ignoreTimes = 0, loc_t startPos = 0);
            virtual loc_t find_block_branch_ref(loc_t pos, int limit, int ignoreTimes = 0, loc_t startPos = 0);
            virtual uint64_t find_register_value(loc_t where, int reg, loc_t startAddr = 0);
            virtual loc_t findnops(uint16_t nopCnt, bool useNops = true, uint32_t nopOpcode = 0);
            virtual loc_t memmem(const void *little, size_t little_len, patchfinder::loc_t startLoc = 0) const;
            virtual loc_t memstr(const char *str) const;
            virtual loc_t deref(loc_t pos) const;
#pragma mark provider

            /*
                Patch replace strings (or raw bytes).
             */
            std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement);
            
#pragma mark static
            static void fail_unimplemented [[noreturn]] (void);
        };
    };
}

#define FAIL_UNIMPLEMENTED tihmstar::patchfinder::patchfinder::fail_unimplemented()


#endif /* patchfinder_hpp */
