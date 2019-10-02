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
    
    ibootpatchfinder64 ibp(argv[1]);
    
    ibp.get_unlock_nvram_patch();
    
    
    printf("done\n");
    return 0;
}
