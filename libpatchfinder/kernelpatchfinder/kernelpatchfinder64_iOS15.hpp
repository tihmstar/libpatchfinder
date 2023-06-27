//
//  kernelpatchfinder64_iOS15.hpp
//  libpatchfinder
//
//  Created by tihmstar on 21.03.22.
//

#ifndef kernelpatchfinder64_iOS15_hpp
#define kernelpatchfinder64_iOS15_hpp

#include "kernelpatchfinder64_iOS13.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS15 : public kernelpatchfinder64_iOS13{
    public:
        using kernelpatchfinder64_iOS13::kernelpatchfinder64_iOS13;

        virtual loc_t find_kernel_map() override;
        virtual loc_t find_kerneltask() override;
        virtual loc_t find_allproc() override;
        virtual loc_t find_kerncontext() override;
        virtual loc_t find_vnode_getattr() override;
        virtual loc_t find_proc_p_flag_offset() override;
        virtual loc_t find_kmem_free() override;
        
        virtual loc_t find_machtrap_table() override;
        virtual loc_t find_function_for_machtrap(int trapcall) override;

        virtual loc64_t find_IOGeneralMemoryDescriptor_ranges_offset() override;
        virtual loc64_t find_IOSurface_MemoryDescriptor_offset() override;


        virtual std::vector<patch> get_always_get_task_allow_patch() override;
        
        virtual std::vector<patch> get_tfp0_patch() override;
        
        virtual std::vector<patch> get_task_conversion_eval_patch() override;
        
        virtual std::vector<patch> get_trustcache_true_patch() override;
        
        /*
         Insert shellcode for vfs_context_current
         */
        
        virtual std::vector<patch> get_insert_vfs_context_current_patch(loc64_t &loc) override;
        
        virtual std::vector<patch> get_insert_setuid_patch() override;
        
        virtual std::vector<patch> get_apfs_root_from_sealed_livefs_patch() override;

        virtual std::vector<patch> get_tfp_anyone_allow_patch() override;
        
        virtual std::vector<patch> get_kernelbase_syscall_patch() override;
        
        virtual std::vector<patch> get_kcall_syscall_patch() override;
    };
}
}
#endif /* kernelpatchfinder64_iOS15_hpp */
