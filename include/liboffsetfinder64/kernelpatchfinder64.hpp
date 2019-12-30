//
//  kernelpatchfinder64.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef kernelpatchfinder64_hpp
#define kernelpatchfinder64_hpp

#include <liboffsetfinder64/machopatchfinder64.hpp>

namespace tihmstar {
    namespace offsetfinder64 {
        class kernelpatchfinder64 : public machopatchfinder64{
            
        public:
            kernelpatchfinder64(const char *filename);
            kernelpatchfinder64(const void *buffer, size_t bufSize);
            
            loc_t find_syscall0();
            loc_t find_machtrap_table();
            loc_t find_function_for_syscall(int syscall);
            loc_t find_function_for_machtrap(int trapcall);

            loc_t find_kerneltask();

            std::vector<patch> get_MarijuanARM_patch();            
            std::vector<patch> get_task_conversion_eval_patch();
            std::vector<patch> get_vm_fault_internal_patch();

            std::vector<patch> get_trustcache_true_patch();

            std::vector<patch> get_mount_patch();

            std::vector<patch> get_tfp0_patch();

            
//            std::vector<patch> get_disable_codesigning_patch();

            
            //        /*------------------------ v0rtex -------------------------- */
            //        offsetfinder64::loc_t find_zone_map();
            //        offsetfinder64::loc_t find_kernel_map();
            //        offsetfinder64::loc_t find_kernel_task();
            //        offsetfinder64::loc_t find_realhost();
            //        offsetfinder64::loc_t find_bzero();
            //        offsetfinder64::loc_t find_bcopy();
            //        offsetfinder64::loc_t find_copyout();
            //        offsetfinder64::loc_t find_copyin();
            //        offsetfinder64::loc_t find_ipc_port_alloc_special();
            //        offsetfinder64::loc_t find_ipc_kobject_set();
            //        offsetfinder64::loc_t find_ipc_port_make_send();
            //        offsetfinder64::loc_t find_chgproccnt();
            //        offsetfinder64::loc_t find_kauth_cred_ref();
            //        offsetfinder64::loc_t find_osserializer_serialize();
            //        uint32_t             find_vtab_get_external_trap_for_index();
            //        uint32_t             find_vtab_get_retain_count();
            //        uint32_t             find_iouserclient_ipc();
            //        uint32_t             find_ipc_space_is_task();
            //        uint32_t             find_ipc_space_is_task_11();
            //        uint32_t             find_proc_ucred();
            //        uint32_t             find_task_bsd_info();
            //        uint32_t             find_vm_map_hdr();
            //        uint32_t             find_task_itk_self();
            //        uint32_t             find_task_itk_registered();
            //        uint32_t             find_sizeof_task();
            //
            //        offsetfinder64::loc_t find_rop_add_x0_x0_0x10();
            //        offsetfinder64::loc_t find_rop_ldr_x0_x0_0x10();
            //        offsetfinder64::loc_t find_exec(std::function<bool(offsetfinder64::insn &i)>cmpfunc);
            //
            //
            //        /*------------------------ kernelpatches -------------------------- */
            //        offsetfinder64::patch find_i_can_has_debugger_patch_off();
            //        offsetfinder64::patch find_lwvm_patch_offsets();
            //        offsetfinder64::patch find_remount_patch_offset();
            //        std::vector<offsetfinder64::patch> find_nosuid_off();
            //        offsetfinder64::patch find_proc_enforce();
            //        offsetfinder64::patch find_amfi_patch_offsets();
            //        offsetfinder64::patch find_cs_enforcement_disable_amfi();
            //        offsetfinder64::patch find_amfi_substrate_patch();
            //        offsetfinder64::patch find_sandbox_patch();
            //        offsetfinder64::loc_t find_sbops();
            //        offsetfinder64::patch find_nonceEnabler_patch();
            //        offsetfinder64::patch find_nonceEnabler_patch_nosym();
            //
            //
            //        /*------------------------ KPP bypass -------------------------- */
            //        offsetfinder64::loc_t find_gPhysBase();
            //        offsetfinder64::loc_t find_gPhysBase_nosym();
            //        offsetfinder64::loc_t find_kernel_pmap();
            //        offsetfinder64::loc_t find_kernel_pmap_nosym();
            //        offsetfinder64::loc_t find_cpacr_write();
            //        offsetfinder64::loc_t find_idlesleep_str_loc();
            //        offsetfinder64::loc_t find_deepsleep_str_loc();
            //
            /*------------------------ Util -------------------------- */
            offsetfinder64::loc_t find_rootvnode();
            offsetfinder64::loc_t find_allproc();
        };
    };
};

#endif /* kernelpatchfinder64_hpp */
