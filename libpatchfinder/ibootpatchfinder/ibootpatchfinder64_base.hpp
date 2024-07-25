//
//  ibootpatchfinder64.hpp
//  libpatchfinder
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef ibootpatchfinder64_base_hpp
#define ibootpatchfinder64_base_hpp

#include <vector>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <libpatchfinder/ibootpatchfinder/ibootpatchfinder64.hpp>
#include <libpatchfinder/patch.hpp>

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder64_base : public ibootpatchfinder64{
            void init();
        public:
            ibootpatchfinder64_base(const char *filename);
            ibootpatchfinder64_base(const void *buffer, size_t bufSize, bool takeOwnership = false);

            virtual ~ibootpatchfinder64_base() override;
            
            virtual bool has_kernel_load() override;
            virtual bool has_recovery_console() override;

            /*
                Make iBoot think we're in production mode, even if we demoted
             */
            virtual std::vector<patch> get_always_production_patch() override;

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
            virtual std::vector<patch> get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr) override;
            
            /*
               make an iBoot command be an arbitrary call gadget with the interface <cmd> <addr> [arg0, arg1, ...]
             */
            virtual std::vector<patch> get_cmd_handler_callfunc_patch(const char *cmd_handler_str) override;
            
            /*
             replace command with: "memcpy <dst> <src> <size>"
             */
            virtual std::vector<patch> replace_cmd_with_memcpy(const char *cmd_handler_str) override;

            /*
                
             */
            virtual std::vector<patch> get_ra1nra1n_patch() override;

            
            /*
                allows reading and writing any nvram variable
             */
            virtual std::vector<patch> get_unlock_nvram_patch() override;
            
            /*
                makes saveenv function do nothing
             */
            virtual std::vector<patch> get_nvram_nosave_patch() override;

            /*
                disable unsetting environment variables
             */
            virtual std::vector<patch> get_nvram_noremove_patch() override;
            
            /*
                get a fresh nonce every time we need a nonce
             */
            virtual std::vector<patch> get_freshnonce_patch() override;

            /*
                remove setpicture 0x100000 sizelimit
             */
            virtual std::vector<patch> get_large_picture_patch() override;
            
            /*
                Pinmux debug UART on ATV4K
             */
            virtual std::vector<patch> get_atv4k_enable_uart_patch() override;
            
            virtual std::vector<patch> get_tz0_lock_patch() override;
            
            /*
                Ignore force_dfu in iBoot
             */
            virtual std::vector<patch> get_no_force_dfu_patch() override;                        
        };
    };
};

#endif /* ibootpatchfinder64_base_hpp */
