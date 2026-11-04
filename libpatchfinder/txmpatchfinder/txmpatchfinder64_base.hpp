//
//  txmpatchfinder64_base.hpp
//  libpatchfinder
//
//  Created by erd on 13.10.26.
//

#ifndef txmpatchfinder64_base_hpp
#define txmpatchfinder64_base_hpp

#include <libpatchfinder/txmpatchfinder/txmpatchfinder64.hpp>

namespace tihmstar {
namespace patchfinder {
    class txmpatchfinder64_base : public txmpatchfinder64{
        
    public:
        txmpatchfinder64_base(const char *filename);
        txmpatchfinder64_base(const void *buffer, size_t bufSize, bool takeOwnership = false);
        txmpatchfinder64_base(txmpatchfinder64 &&mv);
        virtual ~txmpatchfinder64_base() override;
        
#pragma mark Patch finders
        virtual std::vector<patch> get_codesignature_patches() override;
    };
}
}
#endif /* txmpatchfinder64_base_hpp */
