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
    virtual void SetBinaryMetaData(BinaryMetaData *pBinaryMetaData, int fileID = 0)
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

    virtual void AddBasicBlock(BasicBlock &basicBlock, int fileID = 0)
    {
    }

    virtual void AddControlFlow(ControlFlow &controlFlow, int fileID = 0)
    {
    }

    virtual list<AddressRange> ReadFunctionMemberAddresses(int fileID, va_t functionAddress)
    {
        list<AddressRange> ret;
        return ret;
    }
};
