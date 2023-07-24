//
//  StableHash.h
//  libpatchfinder
//
//  Created by tihmstar on 22.07.23.
//

#ifndef StableHash_h
#define StableHash_h

#include <stdint.h>
#include <iostream>
namespace clang{
    uint16_t getPointerAuthStringDiscriminator(std::string string);
};

#endif /* StableHash_h */
