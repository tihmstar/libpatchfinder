//
//  kernelpatchfinder64_iOS16.hpp
//  libpatchfinder
//
//  Created by tihmstar on 08.06.22.
//

#ifndef kernelpatchfinder64_iOS16_hpp
#define kernelpatchfinder64_iOS16_hpp

#include "kernelpatchfinder64_iOS15.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS16 : public kernelpatchfinder64_iOS15{
    public:
        using kernelpatchfinder64_iOS15::kernelpatchfinder64_iOS15;
                
#pragma mark Info finders
        virtual offset_t find_kernel_el() override;

#pragma mark Offset finders
        virtual offset_t find_struct_kqworkloop_offset_kqwl_owner() override;
        virtual offset_t find_struct_task_offset_thread_count() override;
        virtual offset_t find_struct_thread_offset_map() override;
        virtual offset_t find_struct_thread_offset_thread_id() override;
        virtual offset_t find_struct__vm_map_offset_vmu1_lowest_unnestable_start() override;

        virtual offset_t find_ACT_CONTEXT() override;
        virtual offset_t find_ACT_CPUDATAP() override;
        virtual offset_t find_TH_KSTACKPTR() override;

        virtual offset_t find_elementsize_for_zone(const char *zonedesc) override;

        virtual offset_t find_sizeof_struct_proc() override;
        virtual offset_t find_sizeof_struct_task() override;
        virtual offset_t find_sizeof_struct_thread() override;
        virtual offset_t find_sizeof_struct_uthread() override;
        virtual offset_t find_sizeof_struct__vm_map() override;

#pragma mark Location finders
        virtual loc_t find_boot_args_commandline_offset() override;
        virtual loc_t find_sbops() override;
        virtual loc_t find_cdevsw() override;
        virtual loc_t find_gPhysBase() override;
        virtual loc_t find_gVirtBase() override;
        virtual loc_t find_perfmon_devices() override;
        virtual loc_t find_ptov_table() override;
        virtual loc_t find_vm_first_phys_ppnum() override;
        virtual loc_t find_vm_pages() override;
        virtual loc_t find_vm_page_array_beginning_addr() override;
        virtual loc_t find_vm_page_array_ending_addr() override;
        virtual loc_t find_function_vn_kqfilter() override;
        virtual loc_t find_cpu_ttep() override;
        virtual loc_t find_exception_return() override;
        virtual loc_t find_exception_return_after_check() override;
        virtual loc_t find_exception_return_after_check_no_restore() override;
        virtual loc_t find_gxf_ppl_enter() override;
        virtual loc_t find_kalloc_data_external() override;
        virtual loc_t find_kernel_pmap() override;
        virtual loc_t find_ml_sign_thread_state() override;
        virtual loc_t find_pmap_create_options() override;
        virtual loc_t find_pmap_enter_options_addr() override;
        virtual loc_t find_stub_for_pplcall(uint8_t pplcall) override;
        virtual loc_t find_pmap_nest() override;
        virtual loc_t find_pmap_remove_options() override;
        virtual loc_t find_ppl_bootstrap_dispatch() override;
        virtual loc_t find_ppl_handler_table() override;

#pragma mark Patch finders
        virtual std::vector<patch> get_trustcache_true_patch() override;
        
        virtual std::vector<patch> get_codesignature_patches() override;
        
        virtual std::vector<patch> get_force_boot_ramdisk_patch() override;
        
        virtual std::vector<patch> get_read_bpr_patch_with_params(int syscall, loc_t bpr_reg_addr, loc_t ml_io_map, loc_t kernel_map, loc_t kmem_free) override;
        
        virtual std::vector<patch> get_mount_patch() override;
        
        virtual std::vector<patch> get_apfs_skip_authenticate_root_hash_patch() override;
                
        virtual std::vector<patch> get_sandbox_patch() override;
        
        virtual std::vector<patch> get_task_conversion_eval_patch() override;
    };
}
}
#endif /* kernelpatchfinder64_iOS16_hpp */
