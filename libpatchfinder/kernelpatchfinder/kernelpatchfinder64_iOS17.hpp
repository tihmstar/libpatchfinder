//
//  kernelpatchfinder64_iOS17.hpp
//  libpatchfinder
//
//  Created by erd on 20.06.23.
//

#ifndef kernelpatchfinder64_iOS17_hpp
#define kernelpatchfinder64_iOS17_hpp

#include "kernelpatchfinder64_iOS16.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS17 : public kernelpatchfinder64_iOS16{
    public:
        using kernelpatchfinder64_iOS16::kernelpatchfinder64_iOS16;
        
        virtual std::vector<patch> get_codesignature_patches() override;
    };
}
}

#endif /* kernelpatchfinder64_iOS17_hpp */
