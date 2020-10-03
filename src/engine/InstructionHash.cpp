#include "InstructionHash.h"

void InstructionHashMap::Add(vector<unsigned char> bytes, va_t address)
{
    HashBytes *hashBytes = new HashBytes(address, bytes);
    m_instructionHash.insert(pair<unsigned long, HashBytes*>(GetKey(bytes), hashBytes));
    m_addressToInstructionHashMap.insert(pair <va_t, vector<unsigned char>>(address, bytes));

    unordered_map<vector<unsigned char>, int, InstructionHasher>::iterator it = m_instructionHashCounts.find(bytes);

    if (it != m_instructionHashCounts.end())
    {
        it->second++;
    }
    else
    {
        m_instructionHashCounts.insert(pair<vector<unsigned char>, int>(bytes, 1));
    }
}

unsigned long InstructionHashMap::GetKey(vector<unsigned char> bytes)
{
    unsigned long key = 0;
    int shift = 0;
    for (unsigned char ch : bytes)
    {
        key ^= ch << (shift % 32);
        shift += 8;
    }
    return key;
}

vector<vector<unsigned char>> InstructionHashMap::GetUniqueHashes()
{
    vector<vector<unsigned char>> hashes;
    for (auto& val : m_instructionHashCounts)
    {
        if (val.second == 1)
        {
            hashes.push_back(val.first);
        }
    }
    return hashes;
}

size_t InstructionHashMap::Count(vector<unsigned char> hash)
{
    unordered_map<vector<unsigned char>, int, InstructionHasher>::iterator it = m_instructionHashCounts.find(hash);

    if (it != m_instructionHashCounts.end())
    {
        return it->second;
    }

    return 0;
}

vector<va_t> InstructionHashMap::GetHashMatches(vector<unsigned char> hash)
{
    vector<va_t> addresses;
    unsigned long key = GetKey(hash);
    for (multimap <unsigned long, HashBytes *>::iterator it = m_instructionHash.find(key); it != m_instructionHash.end(); it++)
    {
        if (it->first != key)
            break;

        if (it->second->Bytes == hash)
        {
            addresses.push_back(it->second->Address);
        }
    }
    return addresses;
}    

vector<va_t> InstructionHashMap::GetHashMatches(vector<unsigned char> hash, unordered_set<va_t> targetBlockAddresses)
{
    vector<va_t> addresses;
    unsigned long key = GetKey(hash);

    for (multimap <unsigned long, HashBytes *>::iterator it = m_instructionHash.find(key); it != m_instructionHash.end(); it++)
    {
        if (it->first != key)
            break;

        if (it->second->Bytes == hash)
        {
            if (targetBlockAddresses.find(it->second->Address) != targetBlockAddresses.end())
            {
                addresses.push_back(it->second->Address);
            }
        }
    }
    return addresses;
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

size_t InstructionHashMap::Size()
{
    return m_instructionHash.size();
}

void InstructionHashMap::Clear()
{
    m_instructionHash.clear();
}
