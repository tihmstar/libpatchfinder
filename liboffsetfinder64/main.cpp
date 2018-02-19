//
//  main.cpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <iostream>
#include <liboffsetfinder64/liboffsetfinder64.hpp>

using namespace std;
using namespace tihmstar;

int main(int argc, const char * argv[]) {
    
    offsetfinder64 fi(argv[1]);
    
    {
        uint32_t asd = fi.find_vtab_get_external_trap_for_index();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_osserializer_serialize();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_kauth_cred_ref();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_chgproccnt();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_rop_add_x0_x0_0x10();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_rop_ldr_x0_x0_0x10();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_ipc_port_make_send();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_ipc_kobject_set();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_ipc_port_alloc_special();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_copyin();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_copyout();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_bcopy();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_bzero();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_realhost();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_kernel_task();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_kernel_map();
        cout << hex << (void*)asd << endl;
    }
    {
        patchfinder64::loc_t asd = fi.find_zone_map();
        cout << hex << (void*)asd << endl;
    }
    
    
    
    
    
    
    {
        patchfinder64::patch asd = fi.find_lwvm_patch_offsets();
        cout << hex << (void*)asd._location << endl;
    }
    {
        patchfinder64::patch asd = fi.find_remount_patch_offset();
        cout << hex << (void*)asd._location << endl;
    }
    {
        auto dsa = fi.find_nosuid_off();
        for (const auto &asd :dsa) {
            cout << hex << (void*)asd._location << endl;
        }
    }
    {
        patchfinder64::patch asd = fi.find_proc_enforce();
        cout << hex << (void*)asd._location << endl;
    }
    {
        patchfinder64::patch asd = fi.find_amfi_patch_offsets();
        cout << hex << (void*)asd._location << endl;
    }
    {
        patchfinder64::patch asd = fi.find_i_can_has_debugger_patch_off();
        cout << hex << (void*)asd._location << endl;
    }
    {
        patchfinder64::patch asd = fi.find_sandbox_patch();
        cout << hex << (void*)asd._location << endl;
    }
    {
        patchfinder64::patch asd = fi.find_amfi_substrate_patch();
        cout << hex << (void*)asd._location << endl;
    }
    {
        patchfinder64::patch asd = fi.find_cs_enforcement_disable_amfi();
        cout << hex << (void*)asd._location << endl;
    }
    

    
    std::cout << "Done!\n";
    return 0;
}
