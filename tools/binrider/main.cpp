//
//  main.cpp
//  binrider
//
//  Created by tihmstar on 29.06.23.
//

#include <libgeneral/macros.h>
#include <libpatchfinder/patchfinder32.hpp>
#include <libpatchfinder/patchfinder64.hpp>

#include <getopt.h>
#include <stdlib.h>
#include <functional>

using namespace tihmstar::patchfinder;

static struct option longopts[] = {
    /* Short opts setup */
    { "help",               no_argument,       NULL, 'h' },
    { "base",               required_argument, NULL, 'b' },
    { "raw",                required_argument, NULL, 'r' },

    /* Short opts action */
    { "xref",               required_argument, NULL,  0  },
    { "cref",               required_argument, NULL,  0  },
    { "bref",               required_argument, NULL,  0  },

    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: binrider [OPTIONS]\n");
    printf("Ride an ARM binary by doing quick analysis passes\n\n");
    /* Short opts setup */
    printf("  -h, --help\t\t\t\t\tprints usage information\n");
    printf("  -b, --base\t\t\t\t\tSpecify binary base address\n");
    printf("  -s, --segment <fileoffset,base,size,perm>\tSpecify segment in binary. <perm> can contain any of 'rwx' (eg. 0x2000,0x10000000,0x400,rx)\n");
    printf("  -r, --raw <64/32/32a/32t>\t\t\tSet binary type to 'raw'. You must select parser 64bit, 32bit (arm/thumb)\n");

    /* actions */
    printf("      --bref <address>\t\t\t\tPrint branch refs to address\n");
    printf("      --cref <address>\t\t\t\tPrint call refs to address\n");
    printf("      --xref <address>\t\t\t\tPrint literal refs to address\n");

    
    printf("\n");
}

enum BinaryType {
    kBinaryTypeDefault = 0,
    kBinaryTypeARM64,
    kBinaryTypeARM32,
    kBinaryTypeARM32ARMOnly,
    kBinaryTypeARM32ThumbOnly
};

struct rstruct{
    std::string name;
    std::vector<uint64_t> refs;
    std::function <patchfinder::loc_t(patchfinder::loc_t ref, patchfinder::loc_t start)> func;
};


MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    info("binrider: %s",VERSION_STRING);

    patchfinder *pf = nullptr;
    cleanup([&]{
        safeDelete(pf);
    });
    
    int opt = 0;
    int optindex = 0;
    
    const char *lastArg = NULL;

    uint64_t base = 0;
    
    BinaryType bintype = kBinaryTypeDefault;
    
    std::vector<patchfinder::psegment> segments;
    
    //actions
    rstruct brefs{
        .name = "branch refs",
        .refs = {},
        .func = [&](patchfinder::loc_t ref, patchfinder::loc_t start){
            return pf->find_branch_ref(ref, 0, 0, start);
        }
    };
    rstruct crefs{
        .name = "call refs",
        .refs = {},
        .func = [&](patchfinder::loc_t ref, patchfinder::loc_t start){
            return pf->find_call_ref(ref, 0, start);
        }
    };
    rstruct xrefs{
        .name = "xrefs",
        .refs = {},
        .func = [&](patchfinder::loc_t ref, patchfinder::loc_t start){
            return pf->find_literal_ref(ref, 0, start);
        }
    };

    while ((opt = getopt_long(argc, (char * const*)argv, "hb:r:", longopts, &optindex)) >= 0) {
        switch (opt) {
            case 0:
            {
                std::string curopt = longopts[optindex].name;
                if (curopt == "bref") {
                    brefs.refs.push_back(strtoll(optarg, NULL, 16));
                }else if (curopt == "cref") {
                    crefs.refs.push_back(strtoll(optarg, NULL, 16));
                }else if (curopt == "xref") {
                    xrefs.refs.push_back(strtoll(optarg, NULL, 16));
                }else{
                    reterror("Unknown opt '%s'",curopt.c_str());
                }
                break;
            }
                
            case 'b': //long option "base"
                base = strtoll(optarg, NULL, 16);
                break;
                
            case 'r': //long option "raw"
            {
                if (!strcmp(optarg, "64")){
                    bintype = kBinaryTypeARM64;
                }else if (!strcmp(optarg, "32")){
                    bintype = kBinaryTypeARM32;
                }else if (!strcmp(optarg, "32a")){
                    bintype = kBinaryTypeARM32ARMOnly;
                }else if (!strcmp(optarg, "32t")){
                    bintype = kBinaryTypeARM32ThumbOnly;
                }else{
                    error("Invalid raw type '%'",optarg);
                    return 1;
                }
                
                break;
            }
                
            case 's': //long option "segment"
            {
                reterror("TODO parse segment!");
            }

            case 'h': //long option "help"
                cmd_help();
                return 0;
                
            default:
                cmd_help();
                return -1;
        }
    }
    
    if (argc-optind == 1) {
        argc -= optind;
        argv += optind;
        lastArg = argv[0];
    }else{
        cmd_help();
        return -2;
    }
    
    if (bintype == kBinaryTypeDefault) {
        reterror("not implemented");
    }else{
        info("Setting base to 0x%08llx",base);
        
        switch (bintype) {
            case kBinaryTypeARM64:
                pf = new patchfinder64(base, lastArg, segments);
                break;
                
            case kBinaryTypeARM32:
                pf = new patchfinder32((uint32_t)base, lastArg, segments);
                break;
                
            case kBinaryTypeARM32ARMOnly:
            case kBinaryTypeARM32ThumbOnly:
                reterror("Not implemented!");
                
            default:
                reterror("unexpected bintype %d",bintype);
                break;
        }
    }
    

    {
        int add = (bintype == kBinaryTypeARM64) ? 4 : 2;
        for (auto r : {brefs,crefs,xrefs}){
            for (auto tgt : r.refs) {
                info("Checking %s to 0x%08llx",r.name.c_str(),tgt);
                patchfinder::loc_t ref = 0 - add;
                while (true) {
                    try {
                        if (!(ref = r.func(tgt,ref+add))) break;
                    } catch (...) {
                        break;
                    }
                    info("\tFound %s at 0x%08llx",r.name.c_str(),ref);
                }
            }
        }
    }
    
    info("done");
    return 0;
}
