//
//  kernelpatchfinder64_iOS8.hpp
//  libpatchfinder
//
//  Created by erd on 15.05.24.
//

#ifndef kernelpatchfinder64_iOS8_hpp
#define kernelpatchfinder64_iOS8_hpp

#include "kernelpatchfinder64_base.hpp"

namespace tihmstar {
namespace patchfinder {
    class kernelpatchfinder64_iOS8 : public kernelpatchfinder64_base{
    public:
        using kernelpatchfinder64_base::kernelpatchfinder64_base;
        virtual loc_t find_syscall0() override;
        virtual loc_t find_table_entry_for_syscall(int syscall) override;

    };
}
}
#endif /* kernelpatchfinder64_iOS8_hpp */
