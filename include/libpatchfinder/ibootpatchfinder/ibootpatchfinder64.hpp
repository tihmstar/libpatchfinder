//
//  ibootpatchfinder64.hpp
//  libpatchfinder
//
//  Created by tihmstar on 28.07.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_hpp
#define ibootpatchfinder64_hpp

#include <vector>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <libpatchfinder/patchfinder64.hpp>
#include <libpatchfinder/patch.hpp>

#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder.hpp>

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64 : public patchfinder64, public ibootpatchfinder {
        protected:            
            ibootpatchfinder64(bool freeBuf);
            ibootpatchfinder64(ibootpatchfinder64 &&mv);
        public:
            
            static ibootpatchfinder64 *make_ibootpatchfinder64(const char *filename);
            static ibootpatchfinder64 *make_ibootpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership = false);
            virtual ~ibootpatchfinder64();
            
            virtual loc_t findnops(uint16_t nopCnt, bool useNops = true, uint32_t nopOpcode = 0xd503201f /*nop insn*/) override;
            
            virtual loc64_t find_base() override;
            virtual std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement) override;
        };
    };
};

#endif /* ibootpatchfinder64_hpp */
