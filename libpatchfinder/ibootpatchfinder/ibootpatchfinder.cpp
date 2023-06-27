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

ibootpatchfinder::loc64_t ibootpatchfinder::find_base(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_replace_string_patch(std::string needle, std::string replacement){
    reterror("function not implemented by provider");
}

bool ibootpatchfinder::has_kernel_load(){
    reterror("not implemented by provider");
}

bool ibootpatchfinder::has_recovery_console(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_always_production_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_sigcheck_patch(){
    try {
        return get_sigcheck_img4_patch();
    } catch (...) {
        return get_sigcheck_img3_patch();
    }
}

std::vector<patch> ibootpatchfinder::get_sigcheck_img4_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_sigcheck_img3_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::set_root_ticket_hash(std::vector<uint8_t> hash){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_boot_arg_patch(const char *bootargs){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_debug_enabled_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_cmd_handler_patch(const char *cmd_handler_str, uint64_t ptr){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_cmd_handler_callfunc_patch(const char *cmd_handler_str){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::replace_cmd_with_memcpy(const char *cmd_handler_str){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_ra1nra1n_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_unlock_nvram_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_nvram_nosave_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_nvram_noremove_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_freshnonce_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_large_picture_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_change_reboot_to_fsboot_patch(){
    reterror("not implemented by provider");
}

ibootpatchfinder::loc64_t ibootpatchfinder::find_iBoot_logstr(uint64_t loghex, int skip, uint64_t shortdec){
    reterror("not implemented by provider");
}

uint32_t ibootpatchfinder::get_el1_pagesize(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_rw_and_x_mappings_patch_el1(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_tz0_lock_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_force_septype_local_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_skip_set_bpr_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_always_sepfw_booted_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_atv4k_enable_uart_patch(){
    reterror("not implemented by provider");
}

std::vector<patch> ibootpatchfinder::get_no_force_dfu_patch(){
    reterror("not implemented by provider");
}

#ifdef XCODE
std::vector<patch> ibootpatchfinder::test(){
    reterror("not implemented by provider");
}
#endif
