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

#include "StorageDataStructures.h"
#include "IDAAnalyzer.h"
#include "SQLiteDisassemblyStorage.h"
#include "Log.h"

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

bool FileWriterWrapper(PVOID Context, BYTE Type, PBYTE Data, DWORD Length)
{
    BOOL Status = FALSE;
    HANDLE hFile = (HANDLE)Context;
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD NumberOfBytesWritten;
        Status = WriteFile(
            hFile,
            (LPCVOID)&Type,
            sizeof(Type),
            &NumberOfBytesWritten,
            NULL
        );
        if (Status && sizeof(Type) == NumberOfBytesWritten)
        {
            Status = WriteFile(
                hFile,
                (LPCVOID)&Length,
                sizeof(Length),
                &NumberOfBytesWritten,
                NULL
            );
        }
        else
        {
            Status = FALSE;
        }
        if (Status && sizeof(Length) == NumberOfBytesWritten)
        {
            Status = WriteFile(
                hFile,
                (LPCVOID)Data,
                Length,
                &NumberOfBytesWritten,
                NULL
            );
        }
        else
        {
            Status = FALSE;
        }
        if (Status && Length == NumberOfBytesWritten)
        {
        }
        else
        {
            Status = FALSE;
        }
    }
    return Status;
}

void SaveAnalysis(const char *output_file_path)
{
    long start_tick = GetTickCount();
    LogMessage(1, __FUNCTION__, "output_file_path = [%s]\n", output_file_path);

    if (output_file_path)
    {
        SQLiteDisassemblyStorage disassemblyStorage(output_file_path);
        IDAAnalyzer idaAnalyzer = IDAAnalyzer(&disassemblyStorage);
        idaAnalyzer.Analyze(0, 0, false);
        disassemblyStorage.Close();
    }

    long end_tick = GetTickCount();
    LogMessage(1, __FUNCTION__, "BinKit Analysis Finished %.3f sec\n", (float)(end_tick - start_tick) / 1000);
}

bool idaapi run(size_t arg)
{
    LogMessage(1, __FUNCTION__, "BinKit plugin started...\n");

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
        LogMessage(1, __FUNCTION__, "output_file_path == NULL\n");
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
