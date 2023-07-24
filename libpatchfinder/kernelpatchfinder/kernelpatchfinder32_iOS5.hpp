//
//  kernelpatchfinder32_iOS5.hpp
//  libpatchfinder
//
//  Created by erd on 06.07.23.
//

#ifndef kernelpatchfinder32_iOS5_hpp
#define kernelpatchfinder32_iOS5_hpp

#include "kernelpatchfinder32_base.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder32_iOS5 : public kernelpatchfinder32_base{
    public:
        using kernelpatchfinder32_base::kernelpatchfinder32_base;
        
        virtual std::vector<patch> get_allow_UID_key_patch() override;
        
        virtual std::vector<patch> get_cs_enforcement_disable_amfi_patch() override;
    };
}
}
#endif /* kernelpatchfinder32_iOS5_hpp */
