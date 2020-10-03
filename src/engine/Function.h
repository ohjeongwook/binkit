#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <unordered_set>
#include <list>

#include "Structures.h"
#include "DisassemblyReader.h"
#include "Function.h"
#include "BasicBlocks.h"

using namespace std;
using namespace stdext;

class Function
{
private:
    va_t m_address;
    string m_symbol;
    unordered_set<va_t> m_basicBlockAddresses;

public:
    Function(BasicBlocks* p_basicBlocks = NULL, va_t address = 0);

    va_t GetAddress();
    void AddBasicBlock(va_t address);
    unordered_set<va_t> GetBasicBlockAddresses();
    string GetSymbol();
};
