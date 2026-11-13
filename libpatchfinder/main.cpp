//
//  main.cpp
//  patchfinder
//
//  Created by tihmstar on 06.07.21.
//
#include <libgeneral/macros.h>

#include <iostream>
#include <stdint.h>
#include "elfpatchfinder32.hpp"
#include "machopatchfinder32.hpp"
#include "ibootpatchfinder32.hpp"
#include "ibootpatchfinder64.hpp"
#include "kernelpatchfinder32.hpp"
#include "kernelpatchfinder64.hpp"
#include "txmpatchfinder64.hpp"

#define addpatch(pp) do {\
    auto p = pp; \
    patches.insert(patches.end(), p.begin(), p.end()); \
} while (0)

#define addloc(pp) do {\
    patches.push_back({pp,NULL,0}); \
} while (0)


using namespace tihmstar::patchfinder;

int main(int argc, const char * argv[]) {
    printf("start\n");

    std::vector<patch> patches;
    ibootpatchfinder *ibpf = nullptr;
    kernelpatchfinder *kpf = nullptr;
    txmpatchfinder64 *txmpf = nullptr;
    cleanup([&]{
        safeDelete(txmpf);
        safeDelete(ibpf);
        safeDelete(kpf);
    });
    
    try {
        kpf = kernelpatchfinder64::make_kernelpatchfinder64(argv[1]);
    } catch (...) {
        try {
            kpf = kernelpatchfinder32::make_kernelpatchfinder32(argv[1]);
        } catch (...) {
            try {
                ibpf = ibootpatchfinder64::make_ibootpatchfinder64(argv[1]);
            } catch (...) {
                try {
                    ibpf = ibootpatchfinder32::make_ibootpatchfinder32(argv[1]);
                } catch (...) {
                    txmpf = txmpatchfinder64::make_txmpatchfinder64(argv[1]);
                }
            }
        }
    }
    

//    addpatch(ibpf->get_sigcheck_patch());
//    addpatch(ibpf->get_sigcheck_img4_patch());
//    {
//        const char hash[]="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
//        addpatch(ibpf->set_root_ticket_hash(hash,0x14));
//    }
//    {
//        const char hash[]="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
//        addpatch(ibpf->set_boot_manifest_hash(hash,0x14));
//    }
//    addpatch(ibpf->get_always_production_patch());
//    addpatch(ibpf->get_sigcheck_patch());
//    addpatch(ibpf->get_debug_enabled_patch());
//    addpatch(ibpf->get_replace_string_patch("recovery mode", "ra1nsn0w mode"));
//    addpatch(ibpf->get_cmd_handler_callfunc_patch("devicetree"));
//    addpatch(ibpf->get_tz0_lock_patch());
//    addpatch(ibpf->get_skip_set_bpr_patch());
//    addpatch(ibpf->replace_cmd_with_memcpy("reboot"));
//    addpatch(ibpf->get_force_septype_local_patch());
//    addpatch(ibpf->get_always_sepfw_booted_patch());
//    addpatch(ibpf->get_atv4k_enable_uart_patch());
//    addpatch(ibpf->get_boot_arg_patch("-v serial=3"));
//    addpatch(ibpf->get_honor_nvram_boot_arg_patch());
//    addpatch(ibpf->get_wtf_pwndfu_patch());
//    addpatch(ibpf->get_sep_load_raw_patch());
//    addpatch(ibpf->replace_cmd_with_ra1nra1n("reboot"));
//    addpatch(ibpf->get_ra1nra1n_patch());
//    addpatch(ibpf->get_no_img3_dumplist_patch());


    
//    auto asd = ibpf->find_iBoot_logstr(0x8d3ff3cd3759614,0);
//    debug("asd=0x%016llx",asd);
    
    addpatch(kpf->get_AppleImage3NORAccess_sigcheck_patch());
//    addpatch(kpf->get_noemf_patch());
//    addpatch(kpf->get_codesignature_patches());
//    addpatch(kpf->get_trustcache_true_patch());
//    addpatch(kpf->get_mount_patch());
//    addpatch(kpf->get_proc_enforce_disable_patch());
//    addpatch(kpf->get_no_nonce_entanglement_patch());
//    addpatch(kpf->get_force_NAND_writeable_patch());
//    addpatch(kpf->get_read_bpr_patch());
//    addpatch(kpf->get_trustcache_true_patch());
//    addpatch(kpf->get_allow_sep_boot_skip_stage1());
//    addpatch(kpf->get_kernelbase_syscall_patch());
//    addpatch(kpf->get_insert_setuid_patch());
//    addpatch(kpf->get_sep_is_obliterating_patch());
//    addpatch(kpf->get_ramdisk_detection_patch());
//    addpatch(kpf->get_force_boot_ramdisk_patch());
//    addpatch(kpf->get_apfs_skip_authenticate_root_hash_patch());
//    addpatch(kpf->get_harcode_bootargs_patch("-v serial=3"));
//    addpatch(kpf->get_always_get_task_allow_patch());
//    addpatch(kpf->get_tfp_anyone_allow_patch());
//    addpatch(kpf->get_vm_fault_internal_patch());
//    addpatch(kpf->get_i_can_has_debugger_patch());
//    addpatch(kpf->get_raw_sep_romcmd_patch());
//    addpatch(kpf->get_tfp0_patch());


    
//    addpatch(txmpf->get_codesignature_patches());


//    for (int i=0;; i++) {
//        auto ll = ibpf->find_iBoot_logstr(0x3bdace14b1a9a68,i);
//        printf("0x%016llx\n",ll);
//    }
    
    for (auto p : patches) {
        printf(": Applying patch=0x%016llx : ",p._location);
        for (int i=0; i<p.getPatchSize(); i++) {
            printf("%02x",((uint8_t*)p.getPatch())[i]);
        }
        if (p.getPatchSize() == 8) {
            printf(" 0x%016llx",*(uint64_t*)p.getPatch());
        } else if (p.getPatchSize() == 4) {
            printf(" 0x%08x",*(uint32_t*)p.getPatch());
        } else if (p.getPatchSize() == 2) {
            printf(" 0x%04x",*(uint16_t*)p.getPatch());
        }
        printf("\n");
    }
    

    printf("done\n");
    return 0;
}
