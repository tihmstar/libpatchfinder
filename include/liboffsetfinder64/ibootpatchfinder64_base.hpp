//
//  ibootpatchfinder64.hpp
//  liboffsetfinder64
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

#include <liboffsetfinder64/ibootpatchfinder64.hpp>
#include <liboffsetfinder64/patch.hpp>

namespace tihmstar {
    namespace offsetfinder64 {
        class ibootpatchfinder64_base : public ibootpatchfinder64{
        public:
            ibootpatchfinder64_base(const char *filename);
            ibootpatchfinder64_base(const void *buffer, size_t bufSize, bool takeOwnership = false);

            virtual ~ibootpatchfinder64_base() override;
            
            virtual bool has_kernel_load() override;
            virtual bool has_recovery_console() override;

            
            /*
                disable IM4M value validation (BNCH, ECID ...)
             */
            virtual std::vector<patch> get_sigcheck_patch() override;
            
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
             replace "bgcolor" with command: "memcpy <dst> <src> <size>"
             */
            virtual std::vector<patch> replace_bgcolor_with_memcpy() override;

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

#endif /* ibootpatchfinder64_base_hpp */
