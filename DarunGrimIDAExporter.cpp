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

int idaapi init(void)
{
    return PLUGIN_OK;
}

void idaapi term(void)
{
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

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
void SaveIDAAnalysis(bool ask_file_path)
{
    long start_tick = GetTickCount();

    char orignal_file_path[1024] = { 0, };
    char root_file_path[1024] = { 0, };
    char *input_file_path = NULL;
    get_input_file_path(orignal_file_path, sizeof(orignal_file_path) - 1);
    get_root_filename(root_file_path, sizeof(root_file_path) - 1);

    if (ask_file_path)
    {
        input_file_path = ask_file(true, "*.db", "Select DB File to Output");
        if (input_file_path == NULL)
        {
            LogMessage(1, __FUNCTION__, "input_file_path == NULL\n");
            return;
        }
    }

    LogMessage(1, __FUNCTION__, "input_file_path = [%s]\n", input_file_path);

    if (input_file_path)
    {
        SQLiteDisassemblyStorage disassemblyStorage(input_file_path);
        IDAAnalyzer idaAnalyzer = IDAAnalyzer(&disassemblyStorage);
        idaAnalyzer.Analyze(0, 0, false);
        disassemblyStorage.Close();
    }

    long end_tick = GetTickCount();
    LogMessage(1, __FUNCTION__, "DarunGrim Analysis Finished %.3f sec\n", (float)(end_tick - start_tick) / 1000);
}

bool idaapi run(size_t arg)
{
    SetLogLevel(1);
    LogMessage(1, __FUNCTION__, "DarunGrim plugin started...\n");

    if (arg == 1)
    {
        return false;
    }

    SaveIDAAnalysis(true);
    return true;
}

char comment[] = "This is a DarunGrim IDA Exporter Plugin";
char help[] =
"A DarunGrim Plugin module\n"
"This module let you export disassembly and control flow information as a sqlite database.\n";

char wanted_name[] = "DarunGrim";
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
