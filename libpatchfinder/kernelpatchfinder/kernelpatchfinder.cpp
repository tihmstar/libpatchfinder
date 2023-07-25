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

kernelpatchfinder::~kernelpatchfinder(){
    //
}

const void *kernelpatchfinder::memoryForLoc(loc64_t loc){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_replace_string_patch(std::string needle, std::string replacement){
    FAIL_UNIMPLEMENTED;
}

std::string kernelpatchfinder::get_xnu_kernel_version_number_string(){
    FAIL_UNIMPLEMENTED;
}

std::string kernelpatchfinder::get_kernel_version_string(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_generic_kernelpatches(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_codesignature_patches(){
    FAIL_UNIMPLEMENTED;
}

#pragma mark Offset finders
kernelpatchfinder::offset_t kernelpatchfinder::find_struct_offset_for_PACed_member(const char *strDesc){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_struct_kqworkloop_offset_kqwl_owner(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_struct_task_offset_thread_count(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_struct_thread_offset_map(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_struct_thread_offset_thread_id(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_struct__vm_map_offset_vmu1_lowest_unnestable_start(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_elementsize_for_zone(const char *zonedesc){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_sizeof_struct_proc(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_sizeof_struct_task(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_sizeof_struct_thread(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_sizeof_struct_uthread(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::offset_t kernelpatchfinder::find_sizeof_struct__vm_map(){
    FAIL_UNIMPLEMENTED;
}

#pragma mark Location finders
kernelpatchfinder::loc64_t kernelpatchfinder::find_syscall0(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_machtrap_table(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_table_entry_for_syscall(int syscall){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_function_for_syscall(int syscall){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_function_for_machtrap(int trapcall){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_kerneltask(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_sbops(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_ml_io_map(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_kernel_map(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_kmem_free(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_kerncontext(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_cs_blob_generation_count(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_rootvnode(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_allproc(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_vnode_getattr(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_proc_p_flag_offset(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_pac_tag_ref(uint16_t pactag, int skip, kernelpatchfinder::loc64_t startpos, int limit){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_boot_args_commandline_offset(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_IOGeneralMemoryDescriptor_ranges_offset(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_IOSurface_MemoryDescriptor_offset(){
    FAIL_UNIMPLEMENTED;
}

kernelpatchfinder::loc64_t kernelpatchfinder::find_bss_space(uint32_t bytecnt, bool useBytes){
    FAIL_UNIMPLEMENTED;
}

#pragma mark Patch finders
std::vector<patch> kernelpatchfinder::get_MarijuanARM_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_task_conversion_eval_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_vm_fault_internal_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_trustcache_true_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_mount_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_tfp0_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_cs_enforcement_disable_amfi_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_amfi_validateCodeDirectoryHashInDaemon_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_get_task_allow_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_apfs_snapshot_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_AppleImage3NORAccess_hide_failure_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_insert_setuid_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_sandbox_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_nuke_sandbox_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_i_can_has_debugger_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_force_NAND_writeable_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_always_get_task_allow_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_allow_UID_key_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_ramdisk_detection_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_force_boot_ramdisk_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_read_bpr_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_kernelbase_syscall_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_kcall_syscall_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_insert_vfs_context_current_patch(loc64_t &shellcodeloc){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_harcode_bootargs_patch(std::string bootargs){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_harcode_boot_manifest_patch(std::vector<uint8_t> manifestHash){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_apfs_root_from_sealed_livefs_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_apfs_skip_authenticate_root_hash_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_tfp_anyone_allow_patch(){
    FAIL_UNIMPLEMENTED;
}

std::vector<patch> kernelpatchfinder::get_noemf_patch(){
    FAIL_UNIMPLEMENTED;
}

#ifdef XCODE
std::vector<patch> kernelpatchfinder::test(){
    FAIL_UNIMPLEMENTED;
}
#endif
