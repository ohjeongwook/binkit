#include "InstructionHash.h"

void InstructionHashMap::Add(vector<unsigned char> bytes, va_t address)
{
    m_instructionHashMap.insert(pair <vector<unsigned char>, va_t>(bytes, address));
    m_addressToInstructionHashMap.insert(pair <va_t, vector<unsigned char>>(address, bytes));
}

vector<vector<unsigned char>> InstructionHashMap::GetUniqueHashes()
{
    vector<vector<unsigned char>> hashes;

    for (auto& val : m_instructionHashMap)
    {
        if (m_instructionHashMap.count(val.first))
        {
            hashes.push_back(val.first);
        }
    }
    return hashes;
}

vector<unsigned char> InstructionHashMap::GetInstructionHash(va_t address)
{
    multimap <va_t, vector<unsigned char>>::iterator it = m_addressToInstructionHashMap.find(address);
    if (it != m_addressToInstructionHashMap.end())
    {
        return it->second;
    }
    return {};
}

vector<va_t> InstructionHashMap::GetHashMatches(vector<unsigned char> hash)
{
    vector<va_t> addresses;
    for (multimap <vector<unsigned char>, va_t>::iterator it = m_instructionHashMap.find(hash); it != m_instructionHashMap.end(); it++)
    {
        if (it->first != hash)
            break;
        addresses.push_back(it->second);
    }

    return addresses;
}    

int InstructionHashMap::Count(vector<unsigned char> hash)
{
    return m_instructionHashMap.count(hash);
}

int InstructionHashMap::Size()
{
    return m_instructionHashMap.size();
}

void InstructionHashMap::Clear()
{
    m_instructionHashMap.clear();
}