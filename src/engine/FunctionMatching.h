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


// TODO: Change this to multiple match structure
#define BASIC_BLOCK_MATCH_MAP unordered_map<va_t, BasicBlockMatch *>
#define BASIC_TARGET_BLOCK_MATCH_PAIR pair<va_t, BasicBlockMatch *>
#define BASIC_BLOCK_MATCH_PAIR pair<va_t, BasicBlockMatch *>
#define BASIC_BLOCK_MATCH_PAIR_RETURN std::pair<unordered_map<va_t, BasicBlockMatch *>::iterator, bool>

class BasicBlockList
{
private:
    BASIC_BLOCK_MATCH_MAP m_basic_block_matches;

public:
    bool Add(BasicBlockMatch basicBlockMatch, string prefix = "")
    {
        BASIC_BLOCK_MATCH_MAP::iterator it = m_basic_block_matches.find(basicBlockMatch.Source);
        if (it == m_basic_block_matches.end())
        {
            BOOST_LOG_TRIVIAL(debug) << boost::format(prefix + "BasicBlockList::Add: insert %x - %x MatchRate: %d") % basicBlockMatch.Source % basicBlockMatch.Target % basicBlockMatch.MatchRate;
            BasicBlockMatch* p_basicBlockMatch = new BasicBlockMatch();
            memcpy(p_basicBlockMatch, &basicBlockMatch, sizeof(basicBlockMatch));
            m_basic_block_matches.insert(BASIC_BLOCK_MATCH_PAIR(basicBlockMatch.Source, p_basicBlockMatch));
            return true;
        }
        else
        {
            if (it->second->Target != basicBlockMatch.Target && it->second->MatchRate < basicBlockMatch.MatchRate)
            {
                BOOST_LOG_TRIVIAL(debug) << boost::format(prefix + "BasicBlockList::Add: replace %x - %x (%d) <-- %x - %x (%d)") %
                    it->second->Source % it->second->Target % it->second->MatchRate %
                    basicBlockMatch.Source % basicBlockMatch.Target % basicBlockMatch.MatchRate;
                memcpy(it->second, &basicBlockMatch, sizeof(basicBlockMatch));
                return true;
            }
            else
            {
                BOOST_LOG_TRIVIAL(debug) << boost::format(prefix + "BasicBlockList::Add: not adding %x - %x (%d) <-- %x - %x (%d)") %
                    it->second->Source % it->second->Target % it->second->MatchRate %
                    basicBlockMatch.Source % basicBlockMatch.Target % basicBlockMatch.MatchRate;
            }
        }
        return false;
    }

    vector<BasicBlockMatch*> Get(int exclusionFilter = 0)
    {
        vector<BasicBlockMatch *> basicBlockMatchList;

        for(auto& val : m_basic_block_matches)
        {
            if (val.second->Flags & exclusionFilter)
            {
                continue;
            }
            basicBlockMatchList.push_back(val.second);
        }
        return basicBlockMatchList;
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

    vector<FunctionMatch> GetMatches(int exclusionFilter = 0)
    {
        vector<FunctionMatch> functionMatchList;

        for(auto& val : m_matches)
        {
            for (auto& val2 : val.second)
            {
                FunctionMatch functionMatch;
                functionMatch.SourceFunction = val.first;
                functionMatch.TargetFunction = val2.first;
                functionMatch.BasicBlockMatchList = val2.second.Get(exclusionFilter);
                if (functionMatch.BasicBlockMatchList.size() > 0)
                {
                    functionMatchList.push_back(functionMatch);
                }
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

    bool Add(va_t sourceFunctionAddress, va_t targetFunctionAddress, BasicBlockMatch basicBlockMatch, string prefix = "")
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

        BOOST_LOG_TRIVIAL(debug) << boost::format(prefix + "FunctionMatches::Add: %x (%x) - %x (%x) MatchRate: %d") % 
            sourceFunctionAddress % basicBlockMatch.Source % targetFunctionAddress % basicBlockMatch.Target % basicBlockMatch.MatchRate;

        if (it2->second.Add(basicBlockMatch, prefix + "  "))
        {
            return true;
        }
        return false;
    }

    int Add(va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<BasicBlockMatch> basicBlockMatches, string prefix = "")
    {
        int count = 0;
        for (BasicBlockMatch basicBlockMatch : basicBlockMatches)
        {
            if (Add(sourceFunctionAddress, targetFunctionAddress, basicBlockMatch, prefix))
            {
                count++;
            }
        }

        return count;
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
    int DoFunctionInstructionHashMatch(va_t srcFunctionAddress, va_t targetFunctionAddress);
    int DoInstructionHashMatch();
    int DoControlFlowMatch(va_t address = 0, int matchType = CREF_FROM);
};
