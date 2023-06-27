//
//  kernelpatchfinder.cpp
//  libpatchfinder
//
//  Created by tihmstar on 19.07.21.
//

#include "../../include/libpatchfinder/kernelpatchfinder/kernelpatchfinder.hpp"
#include <libgeneral/macros.h>
#include "../../include/libpatchfinder/OFexception.hpp"

using namespace std;
using namespace tihmstar;
using namespace patchfinder;
using namespace libinsn;

const void *kernelpatchfinder::memoryForLoc(loc64_t loc){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_replace_string_patch(std::string needle, std::string replacement){
    reterror("function not implemented by provider");
}

std::string kernelpatchfinder::get_xnu_kernel_version(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_generic_kernelpatches(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_codesignature_patches(){
    reterror("function not implemented by provider");
}

#pragma mark Location finders
kernelpatchfinder::loc64_t kernelpatchfinder::find_syscall0(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_machtrap_table(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_table_entry_for_syscall(int syscall){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_function_for_syscall(int syscall){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_function_for_machtrap(int trapcall){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_kerneltask(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_sbops(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_ml_io_map(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_kernel_map(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_kmem_free(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_kerncontext(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_cs_blob_generation_count(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_rootvnode(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_allproc(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_vnode_getattr(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_proc_p_flag_offset(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_pac_tag_ref(uint16_t pactag, int skip, kernelpatchfinder::loc64_t startpos, int limit){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_boot_args_commandline_offset(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_IOGeneralMemoryDescriptor_ranges_offset(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_IOSurface_MemoryDescriptor_offset(){
    reterror("function not implemented by provider");
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_bss_space(uint32_t bytecnt, bool useBytes){
    reterror("function not implemented by provider");
}

#pragma mark Patch finders
std::vector<patch> kernelpatchfinder::get_MarijuanARM_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_task_conversion_eval_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_vm_fault_internal_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_trustcache_true_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_mount_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_tfp0_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_cs_enforcement_disable_amfi_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_amfi_validateCodeDirectoryHashInDaemon_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_get_task_allow_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_apfs_snapshot_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_AppleImage3NORAccess_hide_failure_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_insert_setuid_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_sandbox_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_nuke_sandbox_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_i_can_has_debugger_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_force_NAND_writeable_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_always_get_task_allow_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_allow_UID_key_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_ramdisk_detection_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_force_boot_ramdisk_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_read_bpr_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_kernelbase_syscall_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_kcall_syscall_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_insert_vfs_context_current_patch(loc64_t &shellcodeloc){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_harcode_bootargs_patch(std::string bootargs){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_harcode_boot_manifest_patch(std::vector<uint8_t> manifestHash){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_apfs_root_from_sealed_livefs_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_apfs_skip_authenticate_root_hash_patch(){
    reterror("function not implemented by provider");
}

std::vector<patch> kernelpatchfinder::get_tfp_anyone_allow_patch(){
    reterror("function not implemented by provider");
}

#ifdef XCODE
std::vector<patch> kernelpatchfinder::test(){
    reterror("not implemented by provider");
}
#endif
