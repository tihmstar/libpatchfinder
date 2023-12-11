//
//  main.cpp
//  offsetexporter
//
//  Created by tihmstar on 24.07.23.
//

#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>
#include <libpatchfinder/kernelpatchfinder/kernelpatchfinder64.hpp>
#include "reflector_kernelpatchfinder.hpp"

#include <stdlib.h>
#include <functional>

using namespace tihmstar::patchfinder;

void cmd_help(){
    printf("Usage: offsetexporter [SHORTOPTS] \n");
    printf("Ride an ARM binary by doing quick analysis passes\n\n");
    /* Short opts setup */
    printf("  -h            \t\tprints usage information\n");
    printf("  -d            \t\tPrint numbers in DEC instead fof HEC\n");
    printf("  -t <template> \t\tSpecify template file\n");
    printf("  -i <infile>   \t\tSpecify input kernel file\n");
    printf("  -o <outfile>  \t\tSpecify output file\n");

    printf("\n");
    printf("--<PATCH> <TEMPLATENAME> [args...]\n");
    printf("------------------------------------------------------\n\n");
    auto memberlist = offsetexporter::reflect_kernelpatchfinder_member_list();
    for (auto member : memberlist) {
        int didprint = 0;
        didprint += printf("--%s",member.funcname.c_str());
        while (didprint < 50) didprint += printf(" ");
        printf(" <TEMPLATENAME> ");
        for (auto arg : member.funcargs) {
            printf("[%s] ",arg.c_str());
        }
        printf("\n");
    }
    
    printf("\n");
}

struct finder_func{
    std::string funcname;
    std::string templaceName;
    std::vector<std::string> args;
};

std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
    bool didFindAtLeastOneOccurence = false;
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        didFindAtLeastOneOccurence = true;
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    retassure(didFindAtLeastOneOccurence, "Failed to find at least 1 instance of '%s'",from.c_str());
    return str;
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    info("offsetexporter: %s",VERSION_STRING);
    kernelpatchfinder64 *kpf = nullptr;
    cleanup([&]{
        safeDelete(kpf);
    });
    
    const char *infile = NULL;
    const char *outfile = NULL;
    const char *templatefile = NULL;

    std::vector<finder_func> findOffsets;
    
    bool printNumbersInDec = false;
    
    if (argc == 1){
        cmd_help();
        return 0;
    }
    
    {
        finder_func curParseFunc;
        for (int i=1; i<argc; i++) {
            const char *curarg = argv[i];
            char sarg = '\0';
            assure(curarg);
            if (curarg[0] == '-'){
                if ((sarg = curarg[1]) != '-') {
                    //singledash arg
                    switch (sarg) {
                        case 'h':
                            cmd_help();
                            return 0;
                            
                        case 'd':
                            printNumbersInDec = true;
                            break;

                        case 'i':
                            infile = (curarg[2]) ? &curarg[2] : argv[++i];
                            break;

                        case 'o':
                            outfile = (curarg[2]) ? &curarg[2] : argv[++i];
                            break;

                        case 't':
                            templatefile = (curarg[2]) ? &curarg[2] : argv[++i];
                            break;

                        default:
                            reterror("Unexpected arg '-%c'",sarg);
                            break;
                    }
                } else if (curarg[1] == '-'){
                    //doubledash arg
                    if (curParseFunc.funcname.size()){
                        findOffsets.push_back(curParseFunc);
                        curParseFunc.args.clear();
                    }
                    curParseFunc.funcname = &curarg[2];
                    retassure(i+1 < argc, "Missing template arg for func '%s'", curParseFunc.funcname.c_str());
                    curParseFunc.templaceName = argv[++i];
                }
            }else{
                /*
                 everything else is func arguments
                 */
                curParseFunc.args.push_back(curarg);
            }
        }
        if (curParseFunc.funcname.size()){
            findOffsets.push_back(curParseFunc);
            curParseFunc.args.clear();
        }
    }
    
    retassure(infile, "infile not set");
    info("Init KPF('%s')",infile);
    kpf = kernelpatchfinder64::make_kernelpatchfinder64(infile);

    std::string templ;
    if (templatefile){
        std::vector<uint8_t> templ_f = tihmstar::readFile(templatefile);
        templ = {(char*)templ_f.data(),(char*)templ_f.data()+templ_f.size()};
    }
    for (auto method : findOffsets) {
        patch pp(0,NULL,0);
        std::string static_str;
        if (method.funcname == "static") {
            retassure(method.args.size() == 1, "bad number of args for 'static' call! Needs 1");
            pp = patch(offsetexporter::ReturnType_std_string,method.args.at(0).data(),method.args.at(0).size(),NULL,false);
        }else{
            pp = offsetexporter::reflect_kernelpatchfinder(kpf, method.funcname, method.args);
        }
        if (!templatefile){
            templ += method.funcname += "=" + method.templaceName + "\n";
        }
        
        if (pp._location == offsetexporter::ReturnType_std_string) {
            //first check for "magic" locations
            std::string rs = {(char*)pp._patch,(char*)pp._patch+pp._patchSize};
            templ = ReplaceAll(templ, method.templaceName, rs);
        }else if (pp._patchSize == 0){
            //this is a location, not a patch
            uint64_t loc = pp._location;
            char buf[20] = {};
            if (printNumbersInDec) {
                snprintf(buf, sizeof(buf), "%llu",loc);
            }else{
                snprintf(buf, sizeof(buf), "0x%llx",loc);
            }
            templ = ReplaceAll(templ, method.templaceName, buf);
        }else{
            reterror("TODO");
        }
    }

    if (outfile) {
        tihmstar::writeFile(outfile, {templ.data(),templ.data()+templ.size()});
        info("Done writing to file '%s'",outfile);
    }else{
        printf("\n\n\n%s",templ.c_str());
        info("Done");
    }

    return 0;
}
