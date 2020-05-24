#pragma once
#include<iostream>
#include <unordered_set>
#include "StorageDataStructures.h"
#include "Log.h"

using namespace std;
using namespace stdext;

class DisassemblyReader
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

    virtual void ReadFunctionAddressMap(int fileID, unordered_set <va_t>& functionAddressMap)
    {
    }

    virtual char *ReadInstructionHash(int fileID, va_t address)
    {
        return NULL;
    }

    virtual string ReadSymbol(int fileID, va_t address)
    {
        return NULL;
    }

    virtual va_t ReadBlockStartAddress(int fileID, va_t address)
    {
        return 0;
    }

    virtual void ReadBasicBlockHashes(int fileID, char *conditionStr, DisassemblyHashMaps *DisassemblyHashMaps)
    {
        return;
    }

    virtual multimap <va_t, PControlFlow> *ReadControlFlow(int fileID, va_t address = 0, bool isFunction = false)
    {
        return NULL;
    }

    virtual list<AddressRange> ReadFunctionMemberAddresses(int fileID, va_t functionAddress)
    {
        list<AddressRange> ret;
        return ret;
    }

    virtual string GetOriginalFilePath(int fileID)
    {
        return NULL;
    }

    virtual char *ReadDisasmLine(int fileID, va_t startAddress)
    {
        return NULL;
    }

    virtual BasicBlock *ReadBasicBlock(int fileID, va_t address)
    {
        return NULL;
    }

    virtual void UpdateBasicBlock(int fileID, va_t address1, va_t address2)
    {
    }
};
