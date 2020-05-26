#pragma once
#include "StorageDataStructures.h"

class hash_compare_instruction_hash
{
public:
    enum
    {
        bucket_size = 400000,
        min_buckets = 4000
    };
public:
    size_t operator() (/*[in]*/ const unsigned char* Bytes) const
    {
        size_t Key = 0;
        for (int i = 0; i < *(unsigned short*)Bytes; i++)
        {
            Key += Bytes[sizeof(short) + i];
        }
        return  Key;
    }
public:
    bool operator() (/*[in]*/const unsigned char* Bytes01,/*[in]*/ const unsigned char* Bytes02) const
    {
        if (Bytes01 == Bytes02)
        {
            return 0;
        }

        if (*(unsigned short*)Bytes01 == *(unsigned short*)Bytes02)
        {
            return (memcmp(Bytes01 + sizeof(unsigned short), Bytes02 + sizeof(unsigned short), *(unsigned short*)Bytes01) < 0);
        }
        return (*(unsigned short*)Bytes01 > * (unsigned short*)Bytes02);
    }
};

void LogMessage(int level, const char* function_name, const char* format, ...);

typedef struct _DisassemblyHashMaps_ {
    FileInfo file_info;
    multimap <unsigned char*, va_t, hash_compare_instruction_hash> instructionHashMap;
    multimap <va_t, unsigned char*> addressToInstructionHashMap;
    multimap <string, va_t> symbolMap;
    multimap <va_t, string> addressToSymbolMap;
    multimap <va_t, PControlFlow> addressToControlFlowMap;
    multimap <va_t, va_t> dstToSrcAddressMap;

    void DumpDisassemblyHashMaps()
    {
        LogMessage(10, __FUNCTION__, "OriginalFilePath = %s\n", file_info.OriginalFilePath);
        LogMessage(10, __FUNCTION__, "ComputerName = %s\n", file_info.ComputerName);
        LogMessage(10, __FUNCTION__, "UserName = %s\n", file_info.UserName);
        LogMessage(10, __FUNCTION__, "CompanyName = %s\n", file_info.CompanyName);
        LogMessage(10, __FUNCTION__, "FileVersion = %s\n", file_info.FileVersion);
        LogMessage(10, __FUNCTION__, "FileDescription = %s\n", file_info.FileDescription);
        LogMessage(10, __FUNCTION__, "InternalName = %s\n", file_info.InternalName);
        LogMessage(10, __FUNCTION__, "ProductName = %s\n", file_info.ProductName);
        LogMessage(10, __FUNCTION__, "ModifiedTime = %s\n", file_info.ModifiedTime);
        LogMessage(10, __FUNCTION__, "MD5Sum = %s\n", file_info.MD5Sum);
        LogMessage(10, __FUNCTION__, "instructionHashMap = %u\n", instructionHashMap.size());
    }
} DisassemblyHashMaps, * PDisassemblyHashMaps;
