//
//  ibootpatchfinder32_base.hpp
//  libpatchfinder
//
//  Created by tihmstar on 07.07.21.
//

#ifndef ibootpatchfinder32_base_hpp
#define ibootpatchfinder32_base_hpp

#include <vector>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder32.hpp>
#include <libpatchfinder/patch.hpp>

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder32_base : public ibootpatchfinder32{
        public:
            ibootpatchfinder32_base(const char *filename);
            ibootpatchfinder32_base(const void *buffer, size_t bufSize, bool takeOwnership = false);

            virtual ~ibootpatchfinder32_base() override;
            
            virtual bool has_kernel_load() override;
            virtual bool has_recovery_console() override;
            
            /*
                patch a wtf image to enter pwndfu
             */
            virtual std::vector<patch> get_wtf_pwndfu_patch() override;

            /*
                disable IMG3 signature validation
             */
            virtual std::vector<patch> get_sigcheck_img3_patch() override;

            /*
                disable IM4M value validation (BNCH, ECID ...)
             */
            virtual std::vector<patch> get_sigcheck_img4_patch() override;
            
            /*
               make kernel boot with these bootargs
             */
            virtual std::vector<patch> get_boot_arg_patch(const char *bootargs) override;

            /*
                //
             */
            virtual std::vector<patch> get_debug_enabled_patch() override;

            /*
               make an iBoot command jump to a specific address
             */
            virtual std::vector<patch> get_cmd_handler_patch(const char *cmd_handler_str, loc64_t ptr) override;
            
            virtual loc64_t find_iBoot_logstr(uint64_t loghex, int skip = 0, uint64_t shortdec = 0) override;
        };
    };
};
#endif /* ibootpatchfinder32_base_hpp */
