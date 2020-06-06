#pragma once
#include<iostream>
#include <unordered_set>
#include "StorageDataStructures.h"
#include "Log.h"

using namespace std;
using namespace stdext;

class DisassemblyReader
{
protected:
    int m_fileId;

public:
    virtual void SetFileInfo(FileInfo *p_file_info)
    {
    }

    virtual void Close()
    {
    }
    
    virtual void SetFileID(int fileId)
    {
        m_fileId = fileId;
    }

    virtual void ReadFunctionAddressMap(unordered_set <va_t>& functionAddressMap)
    {
    }

    virtual char *ReadInstructionHash(va_t address)
    {
        return NULL;
    }

    virtual string ReadSymbol(va_t address)
    {
        return NULL;
    }

    virtual va_t ReadBlockStartAddress(va_t address)
    {
        return 0;
    }

    virtual void ReadBasicBlockHashes(char* conditionStr, DisassemblyHashMaps* DisassemblyHashMaps)
    {
        return;
    }

    virtual void ReadControlFlow(multimap <va_t, PControlFlow>& addressToControlFlowMap, va_t address = 0, bool isFunction = false)
    {
        return;
    }

    virtual list<AddressRange> ReadFunctionMemberAddresses(va_t functionAddress)
    {
        list<AddressRange> ret;
        return ret;
    }

    virtual string GetOriginalFilePath()
    {
        return NULL;
    }

    virtual string ReadDisasmLine(va_t startAddress)
    {
        return NULL;
    }

    virtual BasicBlock *ReadBasicBlock(va_t address)
    {
        return NULL;
    }

    virtual bool UpdateBasicBlock(multimap <va_t, va_t> blockToFunction)
    {
        return false;
    }
};
