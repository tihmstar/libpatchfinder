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

            /*
                disable IM4M value validation (BNCH, ECID ...)
             */
            std::vector<patch> get_sigcheck_patch();
            
            /*
               make kernel boot with these bootargs
             */
            std::vector<patch> get_boot_arg_patch(const char *bootargs);
            
            /*
                //
             */
            std::vector<patch> get_debug_enabled_patch();
            
            /*
               make an iBoot command jump to a specific address
             */
            std::vector<patch> get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr);
            
            /*
             replace "bgcolor" with command: "memcpy <dst> <src> <size>"
             */
            std::vector<patch> replace_bgcolor_with_memcpy();

            /*
                
             */
            std::vector<patch> get_ra1nra1n_patch();

            
            /*
                allows reading and writing any nvram variable
             */
            std::vector<patch> get_unlock_nvram_patch();
            
            /*
                makes saveenv function do nothing
             */
            std::vector<patch> get_nvram_nosave_patch();

            /*
                disable unsetting environment variables
             */
            std::vector<patch> get_nvram_noremove_patch();
            
            /*
                get a fresh nonce every time we need a nonce
             */
            std::vector<patch> get_freshnonce_patch();

//            /*
//                DEVICE2HOST transfers are set addr=getenv("loadaddr")+getenv("filesize");size=0x800000
//                            instead of add=getenv("cmd-results");size=strlen(getenv("cmd-results"))+1
//             */
//            std::vector<patch> get_readback_loadaddr_patch();
//
//            /*
//                replace "memboot" command with "memload",
//                which will load dtre from NAND to getenv("loadaddr")
//             */
//            std::vector<patch> get_memload_patch();

            
        };
    };
};

#endif /* ibootpatchfinder64_hpp */
