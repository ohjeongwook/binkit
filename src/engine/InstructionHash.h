#pragma once
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>
#include "StorageDataStructures.h"

using namespace std;
using namespace stdext;

class InstructionHashMap
{
private:
    multimap <vector<unsigned char>, va_t> m_instructionHashMap;
    multimap <va_t, vector<unsigned char>> m_addressToInstructionHashMap;

public:
    void Add(vector<unsigned char> bytes, va_t address);
    vector<vector<unsigned char>> GetUniqueHashes();
    vector<unsigned char> GetInstructionHash(va_t address);
    vector<va_t> GetHashMatches(vector<unsigned char> hash);
    int Count(vector<unsigned char> hash);
    int Size();
    void Clear();
};
