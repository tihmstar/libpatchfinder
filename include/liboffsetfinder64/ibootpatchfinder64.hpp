//
//  ibootpatchfinder64.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_hpp
#define ibootpatchfinder64_hpp

#include <liboffsetfinder64/patchfinder64.hpp>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <liboffsetfinder64/patch.hpp>
#include <vector>

namespace tihmstar {
    namespace offsetfinder64 {
        class ibootpatchfinder64 : public patchfinder64{
            uint32_t _vers;
        public:
            ibootpatchfinder64(const char *filename);
            ibootpatchfinder64(const void *buffer, size_t bufSize);

            bool has_kernel_load() noexcept;
            bool has_recovery_console() noexcept;

            std::vector<patch> get_boot_arg_patch(const char *bootargs);
            std::vector<patch> get_debug_enabled_patch();
            std::vector<patch> get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr);
            std::vector<patch> get_unlock_nvram_patch();
            
            
            std::vector<patch> get_sigcheck_patch();
            
        };
    };
};

#endif /* ibootpatchfinder64_hpp */
