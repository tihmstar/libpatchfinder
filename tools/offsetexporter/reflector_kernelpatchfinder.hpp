//
//  reflector_kernelpatchfinder.hpp
//  offsetexporter
//
//  Created by tihmstar on 24.07.23.
//

#ifndef reflector_kernelpatchfinder_hpp
#define reflector_kernelpatchfinder_hpp

#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder64.hpp>
#include <iostream>
#include <vector>

namespace tihmstar {
namespace patchfinder {
namespace offsetexporter {
enum ReturnType{
    ReturnType_unknown = 0,
    ReturnType_u64 = 1,
    ReturnType_std_string = 2
};
struct funcs{
    std::string funcname;
    std::vector<std::string> funcargs;
};

    std::vector<funcs> reflect_kernelpatchfinder_member_list(void);

    patch reflect_kernelpatchfinder(kernelpatchfinder64 *kpf, std::string method, std::vector<std::string> args);
};
};
};

#endif /* reflector_kernelpatchfinder_hpp */
