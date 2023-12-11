//
//  kernelpatchfinder32_iOS6.hpp
//  libpatchfinder
//
//  Created by Elcomsoft R&D on 15.03.23.
//

#ifndef kernelpatchfinder32_iOS6_hpp
#define kernelpatchfinder32_iOS6_hpp

#include "kernelpatchfinder32_iOS5.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder32_iOS6 : public kernelpatchfinder32_iOS5{
    public:
        using kernelpatchfinder32_iOS5::kernelpatchfinder32_iOS5;
        
        virtual std::vector<patch> get_amfi_validateCodeDirectoryHashInDaemon_patch() override;
    };
}
}
#endif /* kernelpatchfinder32_iOS6_hpp */
