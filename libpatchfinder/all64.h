//
//  all64.h
//  libpatchfinder
//
//  Created by tihmstar on 09.07.21.
//

#ifndef all64_h
#define all64_h

#define pushINSN(pinsn) do {arm64::insn pinsnn = pinsn; uint32_t opcode = pinsnn.opcode();patches.push_back({pinsnn,&opcode,sizeof(opcode)});} while (0)
#define addPatches(func) do {auto p = func;patches.insert(patches.end(), p.begin(), p.end());} while (0)

#if 1 //with caching
#   define RETCACHEPATCHES do {_savedPatches[__PRETTY_FUNCTION__] = patches; return patches;} while(0)
#   define UNCACHEPATCHES try {return _savedPatches.at(__PRETTY_FUNCTION__);} catch (...) {} std::vector<patch> patches
#   define RETCACHELOC(loc) do {loc_t l = (loc); _savedPatches[__PRETTY_FUNCTION__] = {{l,NULL,0}}; return l;} while(0)
#   define UNCACHELOC try {return _savedPatches.at(__PRETTY_FUNCTION__).front()._location;} catch (...) {}
#else
#   define RETCACHEPATCHES return patches
#   define UNCACHEPATCHES std::vector<patch> patches
#   define RETCACHELOC(loc) do {loc_t l = (loc); return l;} while(0)
#   define UNCACHELOC
#endif

#ifdef DEBUG
static uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); }
static uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) % 2; }
static uint64_t SET_BITS(uint64_t v, int begin) { return ((v)<<(begin));}
#else
#define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1 << ((end)-(begin)+1)) )
#define BIT_AT(v,pos) ( (v >> pos) % 2 )
#define SET_BITS(v, begin) (((v)<<(begin)))
#endif

#endif /* all64_h */
