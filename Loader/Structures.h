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

//,hash_compare<string,equ_str> 
typedef struct _DisassemblyHashMaps_ {
    FileInfo file_info;
    multimap <unsigned char*, va_t, hash_compare_instruction_hash> instruction_hash_map;
    multimap <va_t, unsigned char*> address_to_instruction_hash_map;
    multimap <string, va_t> symbol_map;
    multimap <va_t, PMapInfo> mapInfoMap;
} DisassemblyHashMaps, * PDisassemblyHashMaps;
