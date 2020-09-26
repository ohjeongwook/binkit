#pragma once
#include <unordered_map>

#include "Binary.h"
#include "BasicBlocks.h"

using namespace std;

class DiffAlgorithms;

struct FunctionMatch
{
    va_t SourceFunction;
    va_t TargetFunction;
    vector<BasicBlockMatch *> BasicBlockMatchList;
};

#define BASIC_BLOCK_MATCH_MAP unordered_map<va_t, unordered_map<va_t, BasicBlockMatch *>>
#define BASIC_TARGET_BLOCK_MATCH_PAIR pair<va_t, BasicBlockMatch *>
#define BASIC_BLOCK_MATCH_PAIR pair<va_t, unordered_map<va_t, BasicBlockMatch *>>
#define BASIC_BLOCK_MATCH_PAIR_RETURN std::pair<unordered_map<va_t, unordered_map<va_t, BasicBlockMatch *>>::iterator, bool>

class BasicBlockList
{
private:
    vector<BasicBlockMatch *> m_basic_block_match_list;
    BASIC_BLOCK_MATCH_MAP m_basic_block_matches;

public:
    void Add(BasicBlockMatch basicBlockMatch)
    {
        BASIC_BLOCK_MATCH_MAP::iterator it = m_basic_block_matches.find(basicBlockMatch.Source);

        if (it == m_basic_block_matches.end())
        {
            BASIC_BLOCK_MATCH_PAIR_RETURN result = m_basic_block_matches.insert(BASIC_BLOCK_MATCH_PAIR(basicBlockMatch.Source, {}));
            it = result.first;
        }
        else
        {
            auto it2 = it->second.find(basicBlockMatch.Target);

            if (it2 != it->second.end())
            {
                if (it2->second->MatchRate > basicBlockMatch.MatchRate)
                {
                    return;
                }
            }
        }

        BasicBlockMatch* p_basicBlockMatch = new BasicBlockMatch();
        memcpy(p_basicBlockMatch, &basicBlockMatch, sizeof(basicBlockMatch));
        it->second.insert(BASIC_TARGET_BLOCK_MATCH_PAIR(basicBlockMatch.Target, p_basicBlockMatch));
        m_basic_block_match_list.push_back(p_basicBlockMatch);
    }

    vector<BasicBlockMatch*> Get()
    {
        return m_basic_block_match_list;
    }
};

class FunctionMatches
{
private:
    unordered_map<va_t, unordered_map<va_t, BasicBlockList>> m_matches;

public:
    int GetSize()
    {
        return m_matches.size();
    }

    vector<pair<va_t, va_t>> GetFunctionAddresses()
    {
        vector<pair<va_t, va_t>> functionsAddresses;
        for (auto& val : m_matches)
        {
            for (auto& val2 : val.second)
            {
                functionsAddresses.push_back(pair<va_t, va_t>(val.first, val2.first));
            }
        }
        return functionsAddresses;
    }

    vector<pair<va_t, va_t>> GetFunctionAddresses(va_t address)
    {
        vector<pair<va_t, va_t>> functionsAddresses;
        unordered_map<va_t, unordered_map<va_t, BasicBlockList>>::iterator it = m_matches.find(address);
        if (it != m_matches.end())
        {
            for (auto& val2 : it->second)
            {
                functionsAddresses.push_back(pair<va_t, va_t>(it->first, val2.first));
            }
        }

        return functionsAddresses;
    }

    vector<FunctionMatch> GetMatches()
    {
        vector<FunctionMatch> functionMatchList;

        for(auto& val : m_matches)
        {
            for (auto& val2 : val.second)
            {
                FunctionMatch functionMatch;
                functionMatch.SourceFunction = val.first;
                functionMatch.TargetFunction = val2.first;
                functionMatch.BasicBlockMatchList = val2.second.Get();
                functionMatchList.push_back(functionMatch);
            }
        }
        return functionMatchList;
    }

    vector<FunctionMatch> GetMatchesByAddress(va_t address)
    {
        vector<FunctionMatch> functionMatchList;

        for(auto it = m_matches.find(address); it != m_matches.end(); it++)
        {
            if(it->first != address)
            {
                break;
            }

            va_t sourceFunctionAddress = it->first;
            for (auto& val2 : it->second)
            {
                FunctionMatch functionMatch;
                functionMatch.SourceFunction = sourceFunctionAddress;
                functionMatch.TargetFunction = val2.first;
                functionMatch.BasicBlockMatchList = val2.second.Get();
                functionMatchList.push_back(functionMatch);
            }
        }

        return functionMatchList;
    }

    void Add(va_t sourceFunctionAddress, va_t targetFunctionAddress, BasicBlockMatch basicBlockMatch)
    {
        unordered_map<va_t, unordered_map<va_t, BasicBlockList>>::iterator it = m_matches.find(sourceFunctionAddress);
        if (it == m_matches.end())
        {
            std::pair<unordered_map<va_t, unordered_map<va_t, BasicBlockList>>::iterator, bool > result = m_matches.insert(pair<va_t, unordered_map<va_t, BasicBlockList>>(sourceFunctionAddress, {}));
            it = result.first;
        }

        unordered_map<va_t, BasicBlockList>::iterator it2 = it->second.find(targetFunctionAddress);
        if (it2 == it->second.end())
        {
            std::pair<unordered_map<va_t, BasicBlockList>::iterator, bool > result = it->second.insert(pair<va_t, BasicBlockList>(targetFunctionAddress, {}));
            it2 = result.first;
        }

        it2->second.Add(basicBlockMatch);
    }

    void Add(va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<BasicBlockMatch> basicBlockMatches)
    {
        for (BasicBlockMatch basicBlockMatch : basicBlockMatches)
        {
            Add(sourceFunctionAddress, targetFunctionAddress, basicBlockMatch);
        }
    }
    
    void RemoveMatches(int matchSequence)
    {
        for (auto& val : m_matches)
        {
            for (auto& val2 : val.second)
            {
                /*
                for (auto it = val2.second.begin(); it != val2.second.end(); )
                {
                    if ((*it)->MatchSequence == matchSequence)
                    {
                        it = val2.second.erase(it);
                    }
                    else {
                        ++it;
                    }
                }*/
            }
        }
    }
};

class FunctionMatching
{
private:
    Binary* m_sourceBinary;
    Binary* m_targetBinary;
    DiffAlgorithms* m_pdiffAlgorithms;
    int m_matchSequence;
    FunctionMatches m_functionMatchList;

public:
    FunctionMatching(Binary* p_sourceBinary, Binary* p_targetBinary);
    void AddMatches(vector<BasicBlockMatch> currentBasicBlockMatchList);
    vector<FunctionMatch> GetMatches();
    void RemoveMatches(int matchSequence);
    int DoFunctionInstructionHashMatch(va_t sourceFunctionAddress, va_t targetFunctionAddress);
    int DoInstructionHashMatch();
    int DoControlFlowMatch(va_t address = 0, int matchType = CREF_FROM);
};
