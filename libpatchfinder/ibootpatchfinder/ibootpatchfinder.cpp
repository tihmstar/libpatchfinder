//
//  ibootpatchfinder.cpp
//  libpatchfinder
//
//  Created by tihmstar on 19.07.21.
//

#include "../../include/libpatchfinder/ibootpatchfinder/ibootpatchfinder.hpp"
#include <libgeneral/macros.h>
#include "../../include/libpatchfinder/OFexception.hpp"

using namespace std;
using namespace tihmstar::patchfinder;
using namespace tihmstar::libinsn;

ibootpatchfinder::~ibootpatchfinder(){
    //
}

ibootpatchfinder::loc64_t ibootpatchfinder::find_base(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_replace_string_patch(std::string needle, std::string replacement){
    FAIL_UNIMPLEMENTED;
}

bool ibootpatchfinder::has_kernel_load(){
    FAIL_UNIMPLEMENTED;
}

bool ibootpatchfinder::has_recovery_console(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_wtf_pwndfu_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_always_production_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_sigcheck_patch(){
    try {
        return get_sigcheck_img4_patch();
    } catch (...) {
        return get_sigcheck_img3_patch();
    }
}

std::vector<patch> ibootpatchfinder::get_sigcheck_img4_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_sigcheck_img3_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::set_root_ticket_hash(std::vector<uint8_t> hash){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_boot_arg_patch(const char *bootargs){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_debug_enabled_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_cmd_handler_callfunc_patch(const char *cmd_handler_str){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::replace_cmd_with_memcpy(const char *cmd_handler_str){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_ra1nra1n_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_unlock_nvram_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_nvram_nosave_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_nvram_noremove_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_freshnonce_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_large_picture_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_change_reboot_to_fsboot_patch(){
    FAIL_UNIMPLEMENTED;
}

ibootpatchfinder::loc64_t ibootpatchfinder::find_iBoot_logstr(uint64_t loghex, int skip, uint64_t shortdec){
    FAIL_UNIMPLEMENTED;
}

uint32_t ibootpatchfinder::get_el1_pagesize(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_rw_and_x_mappings_patch_el1(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_tz0_lock_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_force_septype_local_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_sep_load_raw_patch(bool localSEP){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_skip_set_bpr_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_always_sepfw_booted_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_atv4k_enable_uart_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> ibootpatchfinder::get_no_force_dfu_patch(){
    FAIL_UNIMPLEMENTED;
}

#ifdef XCODE
std::vector<patch> ibootpatchfinder::test(){
    FAIL_UNIMPLEMENTED;
}
#endif
