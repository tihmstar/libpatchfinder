//
//  ibootpatchfinder64_iOS18.cpp
//  libpatchfinder
//
//  Created by erd on 15.07.26.
//

#include "ibootpatchfinder64_iOS18.hpp"
#include "../all64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;

std::vector<patch> ibootpatchfinder64_iOS18::get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr){
    /*
        A12 firebloom??
     */
    std::vector<patch> patches;
    std::string handler_str{"A"};
    handler_str+= cmd_handler_str;
    ((char*)handler_str.c_str())[0] = '\0';
    
    loc_t handler_str_loc = -1;
    while (true) {
        try {
            handler_str_loc = memmem(handler_str.c_str(), handler_str.size(), handler_str_loc+1);
        } catch (...) {
            break;
        }
        debug("handler_str_loc=0x%016llx\n",handler_str_loc);
        
        handler_str_loc++;
        
        loc_t tableref = -1;
    retry:
        try {
            tableref = memmem(&handler_str_loc, sizeof(handler_str_loc), tableref+1);
        } catch (...) {
            continue;
        }
        debug("tableref=0x%016llx",tableref);
        {
            loc_t table_funcref = tableref+8*4;
            debug("table_funcref=0x%016llx",table_funcref);
            loc_t handler_func = _vmem->deref(table_funcref);
            debug("handler_func=0x%016llx",handler_func);
            try {
                auto iter = _vmem->getIter(handler_func);
                if (iter() == insn::pacibsp){
                    debug("Hit!");
                    patches.push_back({table_funcref,&ptr,8});
                    continue;
                }
            } catch (...) {
                //
            }
            debug("Fail");
            goto retry;
        }
    }
    if (patches.size()) {
        return patches;
    }

    /*
        Old non-PAC non-firebloom method
     */
    return ibootpatchfinder64_iOS17::get_cmd_handler_patch(cmd_handler_str, ptr);
}
