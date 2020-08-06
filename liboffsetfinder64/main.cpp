//
//  main.cpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <iostream>
#include "kernelpatchfinder64iOS13.hpp"
#include "ibootpatchfinder64.hpp"

using namespace std;
using namespace tihmstar::offsetfinder64;
typedef uint64_t kptr_t;


int main(int argc, const char * argv[]) {

    ibootpatchfinder64 *ibpf = tihmstar::offsetfinder64::ibootpatchfinder64::make_ibootpatchfinder64(argv[1]);
    cleanup([&]{
        delete ibpf;
    });
    
//    auto asd = ibpf->get_boot_arg_patch("-v serial=3");
//
//    loc_t dsa = ibpf->find_iBoot_logstr(0xdce7b01f6ef60a3);

    ibpf->get_disable_wxn_patch();
    
    printf("done\n");
    return 0;
}
