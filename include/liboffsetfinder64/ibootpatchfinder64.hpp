//
//  ibootpatchfinder64.hpp
//  liboffsetfinder64
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

#include <liboffsetfinder64/patchfinder64.hpp>
#include <liboffsetfinder64/patch.hpp>

namespace tihmstar {
    namespace offsetfinder64 {
        class ibootpatchfinder64 : public patchfinder64{
        protected:
            uint32_t _vers;
            
            ibootpatchfinder64(bool freeBuf);
        public:
            
            static ibootpatchfinder64 *make_ibootpatchfinder64(const char *filename);
            static ibootpatchfinder64 *make_ibootpatchfinder64(const void *buffer, size_t bufSize, bool takeOwnership = false);

            
            virtual bool has_kernel_load();
            virtual bool has_recovery_console();

            virtual ~ibootpatchfinder64();
                                    
            /*
                disable IM4M value validation (BNCH, ECID ...)
             */
            virtual std::vector<patch> get_sigcheck_patch();

            /*
               make kernel boot with these bootargs
             */
            virtual std::vector<patch> get_boot_arg_patch(const char *bootargs);
            
            /*
                //
             */
            virtual std::vector<patch> get_debug_enabled_patch();
            
            /*
               make an iBoot command jump to a specific address
             */
            virtual std::vector<patch> get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr);
            
            /*
             replace "bgcolor" with command: "memcpy <dst> <src> <size>"
             */
            virtual std::vector<patch> replace_bgcolor_with_memcpy();

            /*
                
             */
            virtual std::vector<patch> get_ra1nra1n_patch();

            
            /*
                allows reading and writing any nvram variable
             */
            virtual std::vector<patch> get_unlock_nvram_patch();
            
            /*
                makes saveenv function do nothing
             */
            virtual std::vector<patch> get_nvram_nosave_patch();

            /*
                disable unsetting environment variables
             */
            virtual std::vector<patch> get_nvram_noremove_patch();
            
            /*
                get a fresh nonce every time we need a nonce
             */
            virtual std::vector<patch> get_freshnonce_patch();
            
            /*
                replace "reboot" command with "fsboot" command, which boots from filesystem
             */
            virtual std::vector<patch> get_change_reboot_to_fsboot_patch();


            virtual loc_t find_iBoot_logstr(uint64_t loghex, int skip = 0, uint64_t shortdec = 0);
            
            
            virtual uint32_t get_el1_pagesize();
            
            /*
                maps iBoot block writable      at 0x2000000
                maps loadaddr block executable at 0x4000000
             
             */
            
            virtual std::vector<patch> get_rw_and_x_mappings_patch_el1();

            
        };
    };
};

#endif /* ibootpatchfinder64_hpp */
