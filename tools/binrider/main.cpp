//
//  main.cpp
//  binrider
//
//  Created by tihmstar on 29.06.23.
//

#include <libgeneral/macros.h>
#include <libpatchfinder/patchfinder32.hpp>
#include <libpatchfinder/patchfinder64.hpp>
#include <libpatchfinder/machopatchfinder32.hpp>
#include <libpatchfinder/machopatchfinder64.hpp>

#include <functional>
#include <set>

#include <getopt.h>
#include <stdlib.h>

using namespace tihmstar::patchfinder;

static struct option longopts[] = {
    /* Short opts setup */
    { "help",               no_argument,       NULL, 'h' },
    { "base",               required_argument, NULL, 'b' },
    { "raw",                required_argument, NULL, 'r' },

    /* action */
    { "bof",                required_argument, NULL,  0  },
    { "bref",               required_argument, NULL,  0  },
    { "cref",               required_argument, NULL,  0  },
    { "fof" ,               required_argument, NULL,  0  },
    { "stringloc",          required_argument, NULL,  0  },
    { "stringloc2",         required_argument, NULL,  0  },
    { "xref",               required_argument, NULL,  0  },

    /* prints */
    { "Preg",            required_argument, NULL,  0  },

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
    printf("      --bof <address>\t\t\t\tPrint beginning of function for address\n");
    printf("      --bref <address>\t\t\t\tPrint branch refs to address\n");
    printf("      --cref <address>\t\t\t\tPrint call refs to address\n");
    printf("      --fof <address>\t\t\t\tPrint fileoffset of virtual address\n");
    printf("      --stringloc <string>\t\t\t\tPrint addr of null terminated string\n");
    printf("      --stringloc2 <string>\t\t\t\tPrint addr of not null terminated string\n");
    printf("      --xref <address>\t\t\t\tPrint literal refs to address\n");


    /* prints */
    printf("      --Preg <reg>\t\t\t\tPrint regval\n");

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

struct fstruct {
    std::vector<uint8_t> data;
    std::vector<uint64_t> refs;
    bool isString;
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
    std::set<int> Pregs;
    
    //actions
    rstruct bofs{
        .name = "beginning of function",
        .refs = {},
        .func = [&](patchfinder::loc_t pos, patchfinder::loc_t start){
            return pf->find_bof(pos);
        }
    };
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
    rstruct fofs{
        .name = "fileoffset",
        .refs = {},
        .func = [&](patchfinder::loc_t ref, patchfinder::loc_t start){
            pf->deref(ref);
            return ref-pf->find_base();
        }
    };
    rstruct xrefs{
        .name = "xrefs",
        .refs = {},
        .func = [&](patchfinder::loc_t ref, patchfinder::loc_t start){
            return pf->find_literal_ref(ref, 0, start);
        }
    };
    std::vector<fstruct> memLocs;
    
    while ((opt = getopt_long(argc, (char * const*)argv, "hb:r:", longopts, &optindex)) >= 0) {
        switch (opt) {
            case 0:
            {
                std::string curopt = longopts[optindex].name;
                if (curopt == "bof") {
                    bofs.refs.push_back(strtoll(optarg, NULL, 16));
                }else if (curopt == "bref") {
                    brefs.refs.push_back(strtoll(optarg, NULL, 16));
                }else if (curopt == "cref") {
                    crefs.refs.push_back(strtoll(optarg, NULL, 16));
                }else if (curopt == "fof") {
                    fofs.refs.push_back(strtoll(optarg, NULL, 16));
                }else if (curopt.starts_with("stringloc")) {
                    bool isNullTerminated = (curopt == "stringloc");
                    std::string str = optarg;
                    fstruct mLoc = {
                        .data = {str.begin(), str.end()},
                        .isString = true,
                    };
                    if (!isNullTerminated && mLoc.data.size()) {
                        mLoc.data.pop_back();
                    }
                    memLocs.push_back(mLoc);
                }else if (curopt == "xref") {
                    xrefs.refs.push_back(strtoll(optarg, NULL, 16));
                }else if (curopt == "Preg") {
                    Pregs.insert(atoi(optarg));
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
        if (!pf){
            try {
                pf = new machopatchfinder64(lastArg); bintype = kBinaryTypeARM64;
            }catch (tihmstar::exception &e) {
#ifdef DEBUG
                e.dump();
#endif
            }
        }
        if (!pf){
            try {
                pf = new machopatchfinder32(lastArg); bintype = kBinaryTypeARM32;
        }catch (tihmstar::exception &e) {
#ifdef DEBUG
                e.dump();
#endif
            }
        }
        retassure(pf,"not implemented");
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
        //refs
        int add = (bintype == kBinaryTypeARM64) ? 4 : 2;
        char regname = (bintype == kBinaryTypeARM64) ? 'X' : 'R';
        for (auto r : {bofs,brefs,crefs,fofs,xrefs}){
            for (auto tgt : r.refs) {
                info("Checking %s to 0x%08llx",r.name.c_str(),tgt);
                patchfinder::loc_t lasref = 0;
                patchfinder::loc_t ref = 0 - add;
                bool didFind = false;
                while (true) {
                    try {
                        if (!(ref = r.func(tgt,ref+add))) break;
                    } catch (...) {
                        break;
                    }
                    if (ref == lasref) break;
                    info("\tFound %s at 0x%08llx",r.name.c_str(),ref);
                    didFind = true;
                    lasref = ref;
                    for (auto r : Pregs) {
                        auto rv = pf->find_register_value(ref, r);
                        info("\t\t%c: 0x%08llx",regname,rv);
                    }
                }
                if (!didFind) {
                    info("\tNo refs found to 0x%08llx",r.name.c_str());
                }
            }
        }
    }
    
    {
        //memloc
        for (auto m : memLocs) {
            if (m.isString) {
                info("Searching for string '%s'",(char*)m.data.data());
            }else{
                reterror("TODO");
            }
            patchfinder::loc_t found = -1;
            bool didFind = false;
            do{
                try {
                    found = pf->memmem(m.data.data(), m.data.size(),found+1);
                    didFind = true;
                } catch (...) {
                    break;
                }
                if (didFind && found) {
                    if (m.isString) {
                        info("\tFound '%s' at 0x%08llx",(char*)m.data.data(),found);
                    }else{
                        reterror("TODO");
                    }
                }
            } while (found);
            if (!didFind) {
                if (m.isString) {
                    info("\tNo occurences found of '%s'",(char*)m.data.data());
                }else{
                    reterror("TODO");
                }
            }
        }
    }
    
    info("done");
    return 0;
}
