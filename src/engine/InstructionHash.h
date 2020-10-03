#pragma once
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>
#include "StorageDataStructures.h"

using namespace std;
using namespace stdext;

class HashBytes
{
public:
    va_t Address;
    vector<unsigned char> Bytes;

    HashBytes(va_t address, vector<unsigned char> bytes)
    {
        Address = address;
        Bytes = bytes;
    }
};

struct InstructionHasher {
    int operator()(const vector<unsigned char>& v) const {
        int hash = v.size();
        for (auto& i : v) {
            hash ^= i + 0x12345678 + (hash << 6) + (hash >> 2);
        }
        return hash;
    }
};

class InstructionHashMap
{
private:
    multimap <unsigned long, HashBytes *> m_instructionHash;
    unordered_map<vector<unsigned char>, int, InstructionHasher> m_instructionHashCounts;
    multimap <va_t, vector<unsigned char>> m_addressToInstructionHashMap;

    unsigned long GetKey(vector<unsigned char> bytes);

public:
    void Add(vector<unsigned char> bytes, va_t address);
    vector<vector<unsigned char>> GetUniqueHashes();
    size_t Count(vector<unsigned char> hash);

    vector<unsigned char> GetInstructionHash(va_t address);
    vector<va_t> GetHashMatches(vector<unsigned char> hash);
    vector<va_t> GetHashMatches(vector<unsigned char> hash, unordered_set<va_t> targetBlockAddresses);
    size_t Size();
    void Clear();
};
