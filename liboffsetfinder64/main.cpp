//
//  main.cpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <iostream>
#include <liboffsetfinder64/kernelpatchfinder64.hpp>
#include <liboffsetfinder64/ibootpatchfinder64.hpp>

using namespace std;
using namespace tihmstar::offsetfinder64;
typedef uint64_t kptr_t;


int main(int argc, const char * argv[]) {
    
//    ibootpatchfinder64 ibp(argv[1]);
//
//    auto aaa = ibp.get_sigcheck_patch();
//
//    auto patches = ibp.replace_bgcolor_with_memcpy();
//
//    auto asd = ibp.get_ra1nra1n_patch();
//
//    for (auto p : patches) {
//        printf("iBEC: Applying patch=%p : ",(void*)p._location);
//        for (int i=0; i<p._patchSize; i++) {
//            printf("%02x",((uint8_t*)p._patch)[i]);
//        }
//        printf("\n");
//    }
//
    
    const char *little = "asdasd";
    size_t little_len = 4;
    printf("memmem failed to find \"%.*s\"\n",little_len,little);
    
    
    kernelpatchfinder64 kpf(argv[1]);
    try {
        kpf.get_MarijuanARM_patch();
    } catch (tihmstar::exception &e) {
        
        printf("");
    }
//    kpf.get_get_task_allow_patch();

    
    
    
    printf("done\n");
    return 0;
}
