//
//  ibootpatchfinder32_iOS4.cpp
//  libpatchfinder
//
//  Created by erd on 10.07.23.
//

#include <libgeneral/macros.h>

#include "ibootpatchfinder32_iOS4.hpp"
#include "../../include/libpatchfinder/OFexception.hpp"
#include "../all32.h"
#include <string.h>

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

std::vector<patch> ibootpatchfinder32_iOS4::get_sigcheck_img3_patch(){
    std::vector<patch> patches;
    
    //iOS 4.1 //pre-APTicket era
    
    loc_t cert_ref = find_literal_ref_thumb('CERT');
    debug("cert_ref=0x%08x",cert_ref);
    
    loc_t bof = find_bof_thumb(cert_ref);
    debug("bof=0x%08x",bof);
    
    loc_t bref = find_call_ref_thumb(bof);
    debug("bref=0x%08x",bref);
    
    
    loc_t data_ref = find_literal_ref_thumb('DATA');
    debug("data_ref=0x%08x",data_ref);
    
    loc_t dbref = 0;
    for (int i=0; i<0x30; i++){
        try {
            dbref = find_branch_ref_thumb(data_ref-i*2, -0x100);
            data_ref -= i*2;
            debug("Got bref from 0x%08x to data_ref at 0x%08x",dbref,data_ref);
            break;
        } catch (...) {
            continue;
        }
    }
    
    pushINSN(thumb::new_T1_immediate_movs(bref, 0, 0));
    pushINSN(thumb::new_T1_immediate_movs(bref+2, 0, 0));
    
    vmem_thumb iter = _vmemThumb->getIter(data_ref);
    if ((--iter == arm32::str || --iter == arm32::str) && iter().rn() == 13){
        uint8_t rt = iter().rt();
        if ((--iter == arm32::mov || --iter == arm32::mov) && iter().rd() == rt){
            debug("Fixing data_ref");
            data_ref = iter;
            pushINSN(thumb::new_T1_immediate_movs(iter, 0, rt));
            if (iter().insnsize() != 2) {
                pushINSN(thumb::new_T1_immediate_movs(iter.pc()+2, 0, rt));
            }
        }
    }
    
    pushINSN(thumb::new_T2_immediate_b(dbref+2, data_ref));
    pushINSN(thumb::new_T2_immediate_b(dbref+4, data_ref));
    
    return patches;
}
