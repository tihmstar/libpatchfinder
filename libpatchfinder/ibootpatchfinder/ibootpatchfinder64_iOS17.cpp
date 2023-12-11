//
//  ibootpatchfinder64_iOS17.cpp
//  libpatchfinder
//
//  Created by erd on 21.06.23.
//

#include <libgeneral/macros.h>
#include "ibootpatchfinder64_iOS17.hpp"
#include "../all64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm64;


std::vector<patch> ibootpatchfinder64_iOS17::get_force_septype_local_patch(){
    UNCACHEPATCHES;
        
    loc_t loadaddrstr = findstr("loadaddr", true);
    debug("loadaddrstr=0x%016llx",loadaddrstr);

    loc_t filesizestr = findstr("filesize", true);
    debug("filesizestr=0x%016llx",filesizestr);

    loc_t sepiref = -4;
    while ((sepiref = find_literal_ref('sepi',0,sepiref+4))) {
        debug("sepi=0x%016llx",sepiref);
        vmem iter = _vmem->getIter(sepiref);
        for (int i=0; i<4; i++) {
            if (++iter == insn::bl) goto pass_filter1;
        }
        continue;
    pass_filter1:
        uint64_t x1 = find_register_value(iter, 1, iter.pc()-0x20);
        if (x1 != 'sepi') continue;
        
        loc_t bof = find_bof(iter);
        debug("bof=0x%016llx",bof);
        
        loc_t loadaddr_ref = find_literal_ref(loadaddrstr,0,bof);
        debug("loadaddr_ref=0x%016llx",loadaddr_ref);
        if (loadaddr_ref > iter) continue;
        
        vmem iter2 = _vmem->getIter(loadaddr_ref);
        while (++iter2 != insn::bl)
            ;
        
        loc_t call_to_env_get_uint = iter2;
        debug("call_to_env_get_uint=0x%016llx",call_to_env_get_uint);
        
        loc_t env_get_uint = iter2().imm();
        debug("env_get_uint=0x%016llx",env_get_uint);

        loc_t arg0 = find_register_value(iter2, 0, bof);
        debug("arg0=0x%016llx",arg0);
        if (arg0 != loadaddrstr) continue;
        
        while ((++iter2).pc() < iter.pc()) {
            if (iter2().supertype() == insn::sut_branch_imm) {
                goto is_correct_func;
            }
        }
        continue;
    is_correct_func:
        bool fs_load_file_func_is_proxy = false;
        try {
            //now find fs_load_file
            while (true) {
                vmem iter3 = iter2;
                for (int i=0; i<5; i++) {
                    if (--iter3 == insn::add && iter3().rd() == 2 && iter3().rn() == 31) {
                        goto found_fs_load_file;
                    }
                }
                {   //check for proxy
                    iter3 = iter2().imm();
                    for (int i=0; i<5; i++) {
                        if (++iter3 == insn::b) break;
                    }
                    if (iter3() == insn::b){
                        for (int i=0; i<5; i++) {
                            if (--iter3 == insn::add && iter3().rd() == 2 && iter3().rn() == 31) {
                                debug("fs_load_file is a proxy!");
                                fs_load_file_func_is_proxy = true;
                                goto found_fs_load_file;
                            }
                        }
                    }
                }
                while (++iter2 != insn::bl)
                    ;
            }
        } catch (...) {
            continue;
        }
    found_fs_load_file:
        
        {
            loc_t nbof = find_bof(iter2);
            retassure(nbof == bof, "Failed to find fs_load_file. Curloc is out of function");
        }
        
        loc_t fs_load_file = iter2;
        debug("fs_load_file=0x%016llx",fs_load_file);
        
        loc_t ploc = 0;
        if (!fs_load_file_func_is_proxy){
            iter2 -=1;
            ploc = iter2;
        } else {
            reterror("NOT IMPLEMENTED");
        }
        debug("ploc=0x%016llx",ploc);
        pushINSN(insn::new_general_adr(ploc+4*0, filesizestr, 0));
        pushINSN(insn::new_immediate_bl(ploc+4*1, env_get_uint));
        pushINSN(insn::new_immediate_str_unsigned(ploc+4*2, iter2().imm(), iter2().rn(), 0));
        
        addPatches(get_cmd_handler_patch("rsepfirmware", bof));
        break;
    }

    RETCACHEPATCHES;
}
