//
//  kernelpatchfinder.h
//  libpatchfinder
//
//  Created by tihmstar on 19.07.21.
//

#ifndef kernelpatchfinder_h
#define kernelpatchfinder_h

#include <libinsn/vmem.hpp>
#include <libpatchfinder/patch.hpp>
#include <libpatchfinder/patchfinder.hpp>

namespace tihmstar {
    namespace patchfinder {
        class kernelpatchfinder{
        public:
            using loc64_t = tihmstar::libinsn::arm64::insn::loc_t;
            using offset_t = tihmstar::libinsn::arm64::insn::loc_t;
        protected:
            std::vector<std::pair<loc64_t, size_t>> _unusedBSS;
        public:
            virtual ~kernelpatchfinder();

            virtual std::string get_xnu_kernel_version_number_string();
            virtual std::string get_kernel_version_string();
            virtual const void *memoryForLoc(loc64_t loc);
            
            /*
                Patch replace strings (or raw bytes).
             */
            virtual std::vector<patch> get_replace_string_patch(std::string needle, std::string replacement);
                        
#pragma mark Patch collections
            /*
                Provides a set of generic kernelpatches for jailbreaking
             */
            virtual std::vector<patch> get_generic_kernelpatches();

            /*
                Provides a set patches to disable codesignature checks
             */
            virtual std::vector<patch> get_codesignature_patches();

#pragma mark Offset finders
            virtual offset_t find_struct_offset_for_PACed_member(const char *strDesc);
            virtual offset_t find_struct_kqworkloop_offset_kqwl_owner();
            virtual offset_t find_struct_task_offset_thread_count();
            virtual offset_t find_struct_thread_offset_map();

            virtual offset_t find_elementsize_for_zone(const char *zonedesc);

            virtual offset_t find_sizeof_struct_proc();
            virtual offset_t find_sizeof_struct_task();

#pragma mark Location finders
            virtual loc64_t find_syscall0();
            virtual loc64_t find_machtrap_table();
            virtual loc64_t find_table_entry_for_syscall(int syscall);
            virtual loc64_t find_function_for_syscall(int syscall);
            virtual loc64_t find_function_for_machtrap(int trapcall);

            virtual loc64_t find_kerneltask();
            virtual loc64_t find_sbops();
            virtual loc64_t find_cs_blob_generation_count();
            virtual loc64_t find_ml_io_map();
            virtual loc64_t find_kernel_map();
            virtual loc64_t find_kmem_free();
            virtual loc64_t find_kerncontext();
            virtual loc64_t find_rootvnode();
            virtual loc64_t find_allproc();
            virtual loc64_t find_vnode_getattr();
            virtual loc64_t find_proc_p_flag_offset();
            virtual loc64_t find_pac_tag_ref(uint16_t pactag, int skip = 0, loc64_t startpos = 0, int limit = 0);
            virtual loc64_t find_boot_args_commandline_offset();

            virtual loc64_t find_IOGeneralMemoryDescriptor_ranges_offset();
            virtual loc64_t find_IOSurface_MemoryDescriptor_offset();

            virtual loc64_t find_bss_space(uint32_t bytecnt, bool useBytes = true);

#pragma mark Patch finders
            virtual std::vector<patch> get_MarijuanARM_patch();
            virtual std::vector<patch> get_task_conversion_eval_patch();
            virtual std::vector<patch> get_vm_fault_internal_patch();

            virtual std::vector<patch> get_trustcache_true_patch();

            virtual std::vector<patch> get_mount_patch();

            virtual std::vector<patch> get_tfp0_patch();
            
            virtual std::vector<patch> get_cs_enforcement_disable_amfi_patch();
            
            virtual std::vector<patch> get_amfi_validateCodeDirectoryHashInDaemon_patch();

            virtual std::vector<patch> get_get_task_allow_patch();

            virtual std::vector<patch> get_apfs_snapshot_patch();

            virtual std::vector<patch> get_insert_setuid_patch();
            
            /*
                calls to AppleImage3NORAccessUserClient always report success to userspace, even if they failed internally
             */
            virtual std::vector<patch> get_AppleImage3NORAccess_hide_failure_patch();

            /*
                Disables a few sandbox checks required for jailbreaks
             */
            virtual std::vector<patch> get_sandbox_patch();

            /*
                Disables every single sandbox check
             */
            virtual std::vector<patch> get_nuke_sandbox_patch();

            virtual std::vector<patch> get_i_can_has_debugger_patch();
            
            virtual std::vector<patch> get_force_NAND_writeable_patch();
            
            virtual std::vector<patch> get_always_get_task_allow_patch();

            virtual std::vector<patch> get_allow_UID_key_patch();

            virtual std::vector<patch> get_ramdisk_detection_patch();

            /*
                Force booting like 'rd=md0', even if such a bootarg doesn't exist
             */
            virtual std::vector<patch> get_force_boot_ramdisk_patch();

            /*
             Allows reading BPR status with syscall 213
             */
            
            virtual std::vector<patch> get_read_bpr_patch();
            
            /*
             Allows reading kerneltask_addr with syscall 213
             */
            
            virtual std::vector<patch> get_kernelbase_syscall_patch();

            /*
             Allows calling kernel functions with syscall 214
             */
            
            virtual std::vector<patch> get_kcall_syscall_patch();

            /*
             Insert shellcode for vfs_context_current
             */
            
            virtual std::vector<patch> get_insert_vfs_context_current_patch(loc64_t &loc);
            
            virtual std::vector<patch> get_harcode_bootargs_patch(std::string bootargs);
            
            virtual std::vector<patch> get_harcode_boot_manifest_patch(std::vector<uint8_t> manifestHash);

            virtual std::vector<patch> get_apfs_root_from_sealed_livefs_patch();

            virtual std::vector<patch> get_apfs_skip_authenticate_root_hash_patch();

            /*
                No restrictions on calling task_for_pid
             */
            virtual std::vector<patch> get_tfp_anyone_allow_patch();

            virtual std::vector<patch> get_noemf_patch();
#ifdef XCODE
            virtual std::vector<patch> test();
#endif
        };
    };
};

#endif /* kernelpatchfinder_h */
