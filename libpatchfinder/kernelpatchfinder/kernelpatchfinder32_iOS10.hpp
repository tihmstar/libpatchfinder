//
//  kernelpatchfinder32_iOS10.hpp
//  libpatchfinder
//
//  Created by tihmstar on 18.11.26.
//

#ifndef kernelpatchfinder32_iOS10_hpp
#define kernelpatchfinder32_iOS10_hpp

#include "kernelpatchfinder32_iOS9.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder32_iOS10 : public kernelpatchfinder32_iOS9{
    public:
        using kernelpatchfinder32_iOS9::kernelpatchfinder32_iOS9;
        
        virtual std::vector<patch> get_generic_kernelpatches() override;
        
        virtual std::vector<patch> get_lwvm_rw_patch() override;
    };
}
}
#endif /* kernelpatchfinder32_iOS10_hpp */
