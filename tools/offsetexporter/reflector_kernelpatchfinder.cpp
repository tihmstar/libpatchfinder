//
//  reflector_kernelpatchfinder.cpp
//  offsetexporter
//
//  Created by tihmstar on 24.07.23.
//

#include "reflector_kernelpatchfinder.hpp"

using namespace tihmstar::patchfinder;
using offset_t = kernelpatchfinder::offset_t;
using loc64_t = kernelpatchfinder::loc64_t;


#include "reflected_kernelpatchfinder.cpp"
/*
 struct funcdef {
     std::string funcname;
     void *func;
     std::string rettype;
     std::vector<std::string> typeinfo;
 };
 static const std::vector<funcdef> gFuncLookup;
 */

static funcdef lookupMethod(std::string method){
    for (auto &f : gFuncLookup){
        if (f.funcname == method) return f;
    }
    reterror("Failed to lookup method '%s'",method.c_str());
}

std::vector<offsetexporter::funcs> offsetexporter::reflect_kernelpatchfinder_member_list(void){
    std::vector<offsetexporter::funcs> ret;
    for (auto &f : gFuncLookup){
        offsetexporter::funcs func{
            .funcname = f.funcname,
            .funcargs = f.typeinfo
        };
        ret.push_back(func);
    }
    return ret;
}

patch offsetexporter::reflect_kernelpatchfinder(kernelpatchfinder *kpf, std::string method, std::vector<std::string> args){
    void *call_args[4] = {};

    auto fdef = lookupMethod(method);
    retassure(fdef.typeinfo.size() <= 4, "too many args needed");
    ReturnType rettype = ReturnType_unknown;
    
    if (fdef.rettype == "offset_t") {
        rettype = ReturnType_u64;
    }else if (fdef.rettype == "std::string") {
        rettype = ReturnType_std_string;
    }else {
        reterror("unhandled rettype '%s'",fdef.rettype.c_str());
    }
    

    for (int i=0; i<fdef.typeinfo.size(); i++){
        retassure(i < sizeof(call_args)/sizeof(*call_args), "not enough call_args");
        retassure(i < args.size(), "not enough args provided");
        auto ct = fdef.typeinfo.at(i);
        
        if (ct.find("char *") != std::string::npos || ct.find("char*") != std::string::npos) {
            call_args[i] = (void *)args.at(0).c_str();
        }else{
            reterror("handled argument type '%s'",ct.c_str());
        }
    }
    
    switch (rettype) {
        case ReturnType_u64:
        {
            uint64_t (*callfunc)(kernelpatchfinder *, void *, void* ,void *, void *) = (uint64_t (*)(kernelpatchfinder *, void *, void* ,void *, void *))fdef.func;
            uint64_t retU64 = callfunc(kpf,call_args[0],call_args[1],call_args[2],call_args[3]);
            return {retU64, NULL, 0};
        }
            break;
            
        case ReturnType_std_string:
        {
            std::string (*callfunc)(kernelpatchfinder *, void *, void* ,void *, void *) = (std::string (*)(kernelpatchfinder *, void *, void* ,void *, void *))fdef.func;
            std::string retstr = callfunc(kpf,call_args[0],call_args[1],call_args[2],call_args[3]);
            return {ReturnType_std_string, retstr.data(), retstr.size()};
        }
            
        default:
            reterror("unsupported rettype");
    }
}
