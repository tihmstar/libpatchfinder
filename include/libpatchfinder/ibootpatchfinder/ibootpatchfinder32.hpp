//
//  ibootpatchfinder32.hpp
//  libpatchfinder
//
//  Created by tihmstar on 07.07.21.
//

#ifndef ibootpatchfinder32_hpp
#define ibootpatchfinder32_hpp

#include <vector>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <libpatchfinder/patchfinder32.hpp>
#include <libpatchfinder/patch.hpp>

#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder.hpp>

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32 : public patchfinder32, public ibootpatchfinder{
        protected:
            ibootpatchfinder32(bool freeBuf);
        public:
            static ibootpatchfinder32 *make_ibootpatchfinder32(const char *filename);
            static ibootpatchfinder32 *make_ibootpatchfinder32(const void *buffer, size_t bufSize, bool takeOwnership = false);
            virtual ~ibootpatchfinder32();
                        
            virtual loc64_t find_base() override;
            virtual std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement) override;
        };
    };
};
#endif /* ibootpatchfinder32_hpp */
