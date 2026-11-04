//
//  kernelpatchfinder32_iOS3.cpp
//  libpatchfinder
//
//  Created by erd on 18.12.23.
//
#include <libgeneral/macros.h>

#include "kernelpatchfinder32_iOS3.hpp"

#include <libinsn/insn.hpp>
#include "../all32.h"
#include <string.h>

#include <set>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm32;


std::vector<patch> kernelpatchfinder32_iOS3::get_codesignature_patches(){
    std::vector<patch> patches;
    addPatches(get_amfi_validateCodeDirectoryHashInDaemon_patch());
    addPatches(get_cs_enforcement_disable_amfi_patch());
    return patches;
}

std::vector<patch> kernelpatchfinder32_iOS3::get_amfi_validateCodeDirectoryHashInDaemon_patch(){
    UNCACHEPATCHES;
    loc_t memcmp = 0;
    if (haveSymbols()) {
        memcmp = find_sym("_memcmp");
    }else{
        reterror("unimplemented");
    }
    debug("memcmp=0x%08x",memcmp);
    
    /* find*/
    //movs r0, #0x0
    //bx lr
    vmem_thumb ret0 = _vmemThumb->getIter(memcmp);
    while (1) {
        while (++ret0 != arm32::mov || ret0().subtype() != st_immediate || ret0().rd() != 0 || ret0().imm() != 0)
            ;
        if (++ret0 == arm32::bx && ret0().rm() == 14 ){
            --ret0;
            break;
        }
    }
    loc_t ret0_gadget = ret0;
    ret0_gadget |= 1;
    debug("ret0_gadget=0x%08x",ret0_gadget);

    {
        loc_t str = 0;
        try {
            str = findstr("int _validateCodeDirectoryHashInDaemon",false);
        } catch (...) {
            str = findstr("int AppleMobileFileIntegrity::validateCodeDirectoryHashInDaemon",false);
        }
        debug("str=0x%08x",str);
        
        loc_t ref = find_literal_ref_thumb(str);
        if (!ref) ref = find_literal_ref_arm(str);
        debug("ref=0x%08x",ref);
        retassure(ref, "failed to find ref");
        
        {
            loc_t kext_start = ref &~3;
            while (static_cast<uint32_t>(deref(kext_start)) != 0xfeedface)
                kext_start-=4;
            debug("kext_start=0x%08x",kext_start);

            loc_t kext_end = kext_start+4;
            while (static_cast<uint32_t>(deref(kext_end)) != 0xfeedface)
                kext_end+=4;
            debug("kext_end=0x%08x",kext_end);
            
            for (;kext_start < kext_end; kext_start += 4){
                if ((deref(kext_start) & ~1) == (memcmp & ~1)){
                    patches.push_back({kext_start,&ret0_gadget,sizeof(ret0_gadget),slide_ptr});
                }
            }
        }
    }
    RETCACHEPATCHES;
}

std::vector<patch> kernelpatchfinder32_iOS3::get_AppleImage3NORAccess_sigcheck_patch(){
    UNCACHEPATCHES;
    /*
        This function must cover iPhone1,2 (iPhone 3G) and iPhone2,1 (iPhone 3Gs)
        on BOTH iOS 3 and iOS 4
        This is quite tricky, because iOS 3 and iOS 4 is hard to distinguish and 3Gs can use some thumb instructions (cbz) that 3G can't
     */
    
    /*
        iPhone1,1 iOS 3.0
     */
    
    /*
        First patchset
     */
    loc_t str = -1;
    while (true) {
        try {
            str = findstr("Apple Secure Boot Certification Authority", true, str+1);
        } catch (...) {
            retassure(patches.size() > 0, "Failed to find 'Apple Secure Boot Certification Authority' string");
            break;
        }
        debug("str=0x%08x",str);

        if (loc_t ref = find_literal_ref(str)) {
            //thumb mode
            debug("ref=0x%08x",ref);
            
            loc_t bof = find_bof(ref);
            debug("bof=0x%08x",bof);
            
            auto iter = _vmemThumb->getIter(bof);
            while (++iter != arm32::b && iter() != arm32::bcond)
                ;
            
            loc_t p1 = 0;
            if (iter().condition() == cond::NE) {
                p1 = iter().imm();
            }else if (iter().condition() == cond::EQ){
                if (++iter == arm32::b){
                    iter = iter().imm();
                }
                p1 = iter;
            }else{
                reterror("Unexpected condition");
            }
            debug("p1=0x%08x",p1);
            pushINSN(thumb::new_T1_immediate_movs(p1, 0, 0));
            iter = p1;
            if (iter().insnsize() == 4) {
                pushINSN(thumb::new_T1_immediate_movs(p1+2, 0, 0));
            }
        }else{
            /*
                iPhone2,1 0x8900 iOS 4.0 mixes both arm and thumb ._.
             */
            ref = find_literal_ref_arm(str);
            debug("ref=0x%08x",ref);
            
            loc_t bof = find_bof_arm(ref);
            debug("bof=0x%08x",bof);
            
            auto iter = _vmemArm->getIter(bof);
            while (++iter != arm32::b)
                ;
            
            loc_t p1 = iter().imm();
            debug("p1=0x%08x",p1);

            {
                uint32_t opcode = 0xE3A00000;   //mov r0, #0x0
                patches.push_back({p1,&opcode,sizeof(opcode)});
            }
        }
    }

    /*
        Second patchset
     */
    loc_t ref_ecid = find_literal_ref('ECID');
    debug("ref_ecid=0x%08x",ref_ecid);
    auto iter = _vmemThumb->getIter(ref_ecid);
    while (++iter != arm32::bl)
        ;
    
    loc_t img3_val_compare = iter().imm();
    debug("img3_val_compare=0x%08x",img3_val_compare);
    pushINSN(thumb::new_T1_immediate_movs(img3_val_compare, 0, 0));
    pushINSN(thumb::new_T1_general_bx(img3_val_compare+2, 14));

    
    auto aa = _vmemThumb->getIter(0xc05e954e);
    
    /*
        find a function which references all 3, SHSH, DATA, illb
     */
    std::set<loc_t> data_bofs;
    {
        loc_t ref_data = -2;
        loc_t data_bof = NULL;
        while (true) {
            ref_data = find_literal_ref('DATA',0,ref_data+2);
            if (!ref_data) break;
            debug("ref_data=0x%08x",ref_data);
            data_bof = find_bof(ref_data);
            debug("data_bof=0x%08x",data_bof);
            data_bofs.insert(data_bof);
        }
    }
    std::set<loc_t> illb_bofs;
    {
        loc_t ref_illb = -2;
        loc_t illb_bof = NULL;
        while (true) {
            ref_illb = find_literal_ref('illb',0,ref_illb+2);
            if (!ref_illb) break;
            debug("ref_illb=0x%08x",ref_illb);
            illb_bof = find_bof(ref_illb);
            debug("illb_bof=0x%08x",illb_bof);
            illb_bofs.insert(illb_bof);
        }
    }
    loc_t ref_shsh = -2;
    while (true) {
        loc_t shsh_bof = NULL;
        ref_shsh = find_literal_ref('SHSH',0,ref_shsh+2);
        debug("ref_shsh=0x%08x",ref_shsh);
        shsh_bof = find_bof(ref_shsh);
        debug("shsh_bof=0x%08x",shsh_bof);
        if (data_bofs.find(shsh_bof) == data_bofs.end()) continue;
        if (illb_bofs.find(shsh_bof) == illb_bofs.end()) continue;
        break;
    }
    
    iter = ref_shsh;
    while (++iter != arm32::b && iter() != arm32::bcond)
        ;
    
    loc_t badtgt[2] = {};
    for (int i=0; i<2; i++) {
        while (++iter != arm32::b && iter() != arm32::bcond)
            ;
        badtgt[i] = iter().imm();
        loc_t hit = iter;
        debug("hit=0x%08x",hit); //nop this
        pushINSN(thumb::new_T1_immediate_movs(hit, 0, 0));
        if (iter().insnsize() == 4) {
            pushINSN(thumb::new_T1_immediate_movs(hit+2, 0, 0));
        }
    }
    
    while (true){
        while (++iter != arm32::bl)
            ;
        loc_t hit_kill = iter;
        debug("hit_kill=0x%08x",hit_kill);
        while (++iter != arm32::b && iter() != arm32::bcond && iter() != arm32::cbz)
            ;
        if (iter().imm() != badtgt[0] && iter().imm() != badtgt[1]){
            iter = hit_kill;
            continue;
        }
        pushINSN(thumb::new_T1_immediate_movs(hit_kill, 1, 0));
        iter = hit_kill;
        if (iter().insnsize() == 4) {
            pushINSN(thumb::new_T1_immediate_movs(hit_kill+2, 1, 0));
        }
        break;
    }

    RETCACHEPATCHES; 
}
