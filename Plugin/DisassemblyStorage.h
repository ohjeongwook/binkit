#pragma once
#include<iostream>
#include <unordered_set>
#include "StorageDataStructures.h"
#include "Log.h"

using namespace std;
using namespace stdext;

class DisassemblyStorage
{
public:
    virtual void SetFileInfo(FileInfo *p_file_info)
    {
    }

    virtual int BeginTransaction()
    {
        return 0;
    }

    virtual int EndTransaction()
    {
        return 0;
    }

    virtual void Close()
    {
    }

    virtual void AddBasicBlock(PBasicBlock p_basic_block, int fileID = 0)
    {
    }

    virtual void AddMapInfo(PMapInfo p_map_info, int fileID = 0)
    {
    }

    virtual list<AddressRange> ReadFunctionMemberAddresses(int fileID, va_t functionAddress)
    {
        list<AddressRange> ret;
        return ret;
    }

    virtual char *GetOriginalFilePath(int fileID)
    {
        return NULL;
    }

    virtual void UpdateBasicBlock(int fileID, va_t address1, va_t address2)
    {
    }
};
