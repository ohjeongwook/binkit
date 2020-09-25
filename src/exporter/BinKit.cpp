#pragma warning ( disable: 4819 )
#pragma warning ( disable: 4996 )
#pragma warning ( disable : 4786 )

#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <iostream>
#include <list>
#include <graph.hpp>
#include <expr.hpp>
#include <loader.hpp>
#include <diskio.hpp>

#include "StorageDataStructures.h"
#include "IDAAnalyzer.h"
#include "SQLiteDisassemblyStorage.h"
#include "Utility.h"

#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>

using namespace std;

void SaveAnalysis(const char* output_file_path);

static error_t idaapi save_binkit_analysis(idc_value_t* argv, idc_value_t* res)
{
    SaveAnalysis(argv[0].c_str());
    res->num = 0;
    return eOk;
}
static const char save_binkit_analysis_args[] = { VT_STR, 0 };
static const ext_idcfunc_t save_binkit_analysis_desc = {
    "SaveBinKitAnalysis",
    save_binkit_analysis,
    save_binkit_analysis_args,
    NULL,
    0,
    0
};

int idaapi init(void)
{
    add_idc_func(save_binkit_analysis_desc);
    return PLUGIN_OK;
}

void idaapi term(void)
{
    del_idc_func(save_binkit_analysis_desc.name);
}

bool IsNumber(char *data)
{
    bool is_number = TRUE;
    //hex
    if (strlen(data) > 1 && data[strlen(data) - 1] == 'h')
    {
        int i = 0;
        while (i < strlen(data) - 2)
        {
            if (
                ('0' <= data[i] && data[i] <= '9') ||
                ('a' <= data[i] && data[i] <= 'f') ||
                ('A' <= data[i] && data[i] <= 'F')
                )
            {
            }
            else {
                is_number = FALSE;
                break;
            }
            i++;
        }
    }
    else {
        int i = 0;
        while (data[i])
        {
            if ('0' <= data[i] && data[i] <= '9')
            {
            }
            else {
                is_number = FALSE;
                break;
            }
            i++;
        }
    }
    return is_number;
}

void SaveAnalysis(const char *output_file_path)
{
    long start_tick = GetTickCount();
    BOOST_LOG_TRIVIAL(debug) << boost::format("output_file_path = [%s]") % output_file_path;

    if (output_file_path)
    {
        SQLiteDisassemblyStorage disassemblyStorage(output_file_path);
        IDAAnalyzer idaAnalyzer = IDAAnalyzer(&disassemblyStorage);
        idaAnalyzer.Analyze(0, 0, false);
        disassemblyStorage.Close();
    }

    long end_tick = GetTickCount();
    BOOST_LOG_TRIVIAL(debug) << boost::format("BinKit Analysis Finished %.3f sec") % ((float)(end_tick - start_tick) / 1000);
}

bool idaapi run(size_t arg)
{
    string ida_dir = get_user_idadir();
    LoadLogSettings(ida_dir + "\\binkit_logging.ini");
    BOOST_LOG_TRIVIAL(debug) << boost::format("BinKit plugin started...");

    if (arg == 1)
    {
        return false;
    }

    char orignal_file_path[1024] = { 0, };
    char root_file_path[1024] = { 0, };
    get_input_file_path(orignal_file_path, sizeof(orignal_file_path) - 1);
    get_root_filename(root_file_path, sizeof(root_file_path) - 1);

    char* output_file_path = ask_file(true, "*.db", "Select DB File to Output");
    if (output_file_path == NULL)
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format("output_file_path == NULL");
        return false;
    }

    SaveAnalysis(output_file_path);
    return true;
}

char comment[] = "This is a BinKit IDA Exporter Plugin";
char help[] =
"A BinKit Plugin module\n"
"This will generate hash values for basic blocks to be used for identifying similar matching blocks from other binaries.\n";

char wanted_name[] = "BinKit Exporter";
char wanted_hotkey[] = "Alt-8";

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MOD,
    init,
    term,
    run,
    comment,
    help,
    wanted_name,
    wanted_hotkey
};
