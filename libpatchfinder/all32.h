//
//  all32.h
//  libpatchfinder
//
//  Created by tihmstar on 09.07.21.
//

#ifndef all32_h
#define all32_h

#define pushINSN(pinsn) do {auto pinsnn = pinsn; uint32_t opcode = pinsnn.opcode();patches.push_back({(loc_t)pinsnn,&opcode,pinsnn.insnsize()});} while (0)
#define addPatches(func) do {auto p = func;patches.insert(patches.end(), p.begin(), p.end());} while (0)

#ifdef DEBUG
static uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); }
static uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) % 2; }
static uint64_t SET_BITS(uint64_t v, int begin) { return ((v)<<(begin));}
#else
#define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1 << ((end)-(begin)+1)) )
#define BIT_AT(v,pos) ( (v >> pos) % 2 )
#define SET_BITS(v, begin) (((v)<<(begin)))
#endif

#endif /* all32_h */
