//
//  main.cpp
//  offsetfinder64
//
//  Created by tihmstar on 10.01.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <iostream>
#include "kernelpatchfinder64iOS13.hpp"

using namespace std;
using namespace tihmstar::offsetfinder64;
typedef uint64_t kptr_t;


int main(int argc, const char * argv[]) {

    
    kernelpatchfinder64iOS13 kpf(argv[1]);

    kpf.find_cs_blob_generation_count();
    
    
    
    printf("done\n");
    return 0;
}
