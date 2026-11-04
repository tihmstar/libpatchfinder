//
//  kernelpatchfinder64_iOS18.hpp
//  libpatchfinder
//
//  Created by erd on 15.07.26.
//

#ifndef kernelpatchfinder64_iOS18_hpp
#define kernelpatchfinder64_iOS18_hpp

#include "kernelpatchfinder64_iOS17.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS18 : public kernelpatchfinder64_iOS17{
    public:
        using kernelpatchfinder64_iOS17::kernelpatchfinder64_iOS17;
        
        virtual loc_t find_query_trustcache() override;
    };
}
}
#endif /* kernelpatchfinder64_iOS18_hpp */
