//
//  kernelpatchfinder64_iOS8.cpp
//  libpatchfinder
//
//  Created by erd on 15.05.24.
//

#include "kernelpatchfinder64_iOS8.hpp"
#include <libinsn/insn.hpp>
#include "../all64.h"
#include "sbops64.h"
#include <string.h>
#include <set>

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;
using namespace arm64;

patchfinder64::loc_t kernelpatchfinder64_iOS8::find_syscall0(){
    UNCACHELOC;
    constexpr char sig_syscall_3[] = "\x06\x00\x00\x00\x03\x00\x0c\x00";
    patchfinder64::loc_t sys3 = memmem(sig_syscall_3, sizeof(sig_syscall_3)-1);
    loc_t retval = sys3 - (3 * 0x18) + 0x8;
    RETCACHELOC(retval);
}

patchfinder64::loc_t kernelpatchfinder64_iOS8::find_table_entry_for_syscall(int syscall){
    patchfinder64::loc_t syscallTable = find_syscall0();
    return (syscallTable + 3*(syscall-1)*sizeof(uint64_t));
}
