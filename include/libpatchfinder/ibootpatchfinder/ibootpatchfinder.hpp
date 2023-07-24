//
//  ibootpatchfinder.hpp
//  libpatchfinder
//
//  Created by tihmstar on 19.07.21.
//

#ifndef ibootpatchfinder_hpp
#define ibootpatchfinder_hpp

#include <libinsn/vmem.hpp>
#include <vector>

#include <libpatchfinder/patch.hpp>
#include <libpatchfinder/patchfinder.hpp>

namespace tihmstar {
    namespace patchfinder {
        class ibootpatchfinder{
        protected:
            uint32_t _vers;
        public:
            using loc64_t = tihmstar::libinsn::arm64::insn::loc_t;
            virtual ~ibootpatchfinder();

            virtual loc64_t find_base();
            /*
                Patch replace strings (or raw bytes).
             */
            virtual std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement);
            
            
            virtual bool has_kernel_load();
            virtual bool has_recovery_console();
            
            virtual std::vector<patch> get_wtf_pwndfu_patch();

               
            /*
                Make iBoot think we're in production mode, even if we demoted
             */
            virtual std::vector<patch> get_always_production_patch();

            /*
                disable IM4M value validation (BNCH, ECID ...)
             */
            virtual std::vector<patch> get_sigcheck_patch();
            virtual std::vector<patch> get_sigcheck_img4_patch();
            virtual std::vector<patch> get_sigcheck_img3_patch();

            /*
                set root-ticket-hash
             */
            virtual std::vector<patch> set_root_ticket_hash(std::vector<uint8_t> hash);

            
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
            virtual std::vector<patch> get_cmd_handler_patch(const char *cmd_handler_str, loc64_t ptr);

            /*
               make an iBoot command be an arbitrary call gadget with the interface <cmd> <addr> [arg0, arg1, ...]
             */
            virtual std::vector<patch> get_cmd_handler_callfunc_patch(const char *cmd_handler_str);

            /*
             replace command with: "memcpy <dst> <src> <size>"
             */
            virtual std::vector<patch> replace_cmd_with_memcpy(const char *cmd_handler_str);

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
                remove setpicture 0x100000 sizelimit
             */
            virtual std::vector<patch> get_large_picture_patch();
            
            /*
                replace "reboot" command with "fsboot" command, which boots from filesystem
             */
            virtual std::vector<patch> get_change_reboot_to_fsboot_patch();


            virtual loc64_t find_iBoot_logstr(uint64_t loghex, int skip = 0, uint64_t shortdec = 0);
            
            
            virtual uint32_t get_el1_pagesize();
            
            /*
                maps iBoot block writable      at 0x2000000
                maps loadaddr block executable at 0x4000000
             
             */
            
            virtual std::vector<patch> get_rw_and_x_mappings_patch_el1();

            /*
                Skip tz0 locking by iBoot
             */
            virtual std::vector<patch> get_tz0_lock_patch();
            
            /*
                Make iboot accept "sepi" images even when sent from remote.
                This will always reject "rsep" images.
                This will make sure sep image gets propagated to devicetree.
             */
            virtual std::vector<patch> get_force_septype_local_patch();

            /*
                Runs the above 'get_force_septype_local_patch' function, but this time only "rsep" images are accepted
                This may skip some iBoot pre-processing, because without this the image doesn't end up where it should :/
             */
            virtual std::vector<patch> get_sep_load_raw_patch(bool localSEP = false);

            /*
                Skip setting BPR by iBoot
             */
            virtual std::vector<patch> get_skip_set_bpr_patch();
            
            /*
                Always set "sepfw-booted" in devicetree
             */
            virtual std::vector<patch> get_always_sepfw_booted_patch();

            /*
                Pinmux debug UART on ATV4K
             */
            virtual std::vector<patch> get_atv4k_enable_uart_patch();

            /*
                Ignore force_dfu in iBoot
             */
            virtual std::vector<patch> get_no_force_dfu_patch();

#ifdef XCODE
            virtual std::vector<patch> test();
#endif
        };
    };
};
#endif /* ibootpatchfinder_hpp */
