//
//  kernelpatchfinder64_iOS27.hpp
//  libpatchfinder
//
//  Created by erd on 16.09.26.
//

#ifndef kernelpatchfinder64_iOS27_hpp
#define kernelpatchfinder64_iOS27_hpp

#include "kernelpatchfinder64_iOS26.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS27 : public kernelpatchfinder64_iOS26{
    public:
        using kernelpatchfinder64_iOS26::kernelpatchfinder64_iOS26;
        
        virtual loc_t findnops(uint16_t nopCnt, bool useNops = true, uint32_t nopOpcode = 0xd503201f /*nop insn*/) override;

        virtual loc_t find_query_trustcache() override;
        virtual loc_t find_ml_io_map() override;
        virtual std::vector<patch> get_codesignature_patches() override;
        virtual std::vector<patch> get_trustcache_true_patch() override;
        virtual std::vector<patch> get_force_boot_ramdisk_patch() override;
    };
}
}
#endif /* kernelpatchfinder64_iOS27_hpp */
