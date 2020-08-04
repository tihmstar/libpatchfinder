//
//  all_liboffsetfinder.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef all_liboffsetfinder_h
#define all_liboffsetfinder_h

#ifdef DEBUG
#include <stdint.h>
static uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); }
static uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) % 2; }

static uint64_t SET_BITS(uint64_t v, int begin) { return ((v)<<(begin));}


#else
#define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1 << ((end)-(begin)+1)) )
#define BIT_AT(v,pos) ( (v >> pos) % 2 )
#define SET_BITS(v, begin) (((v)<<(begin)))
#endif



#endif /* all_liboffsetfinder_h */
