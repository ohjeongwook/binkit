#include "Structures.h"
#include "Utility.h"
#include "DiffAlgorithms.h"
#include "Diff.h"
#include<algorithm>
#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>

DiffAlgorithms::DiffAlgorithms()
{
    m_debugLevel = 0;
}

DiffAlgorithms::DiffAlgorithms(Binary* p_sourceBinary, Binary* p_targetBinary)
{
    m_debugLevel = 0;
    m_psrcBasicBlocks = p_sourceBinary->GetBasicBlocks();
    m_ptargetBasicBlocks = p_targetBinary->GetBasicBlocks();
    m_psrcInstructionHash = m_psrcBasicBlocks->GetInstructionHashes();
    m_ptargetInstructionHash = m_ptargetBasicBlocks->GetInstructionHashes();    
}

int DiffAlgorithms::GetInstructionHashMatchRate(vector<unsigned char> instructionHash1, vector<unsigned char> instructionHash2)
{
    if (instructionHash1.size() == 0 && instructionHash2.size() == 0)
    {
        return 100;
    }
    return GetStringSimilarity(BytesToHexString(instructionHash1).c_str(), BytesToHexString(instructionHash2).c_str());;
}

vector<BasicBlockMatch> DiffAlgorithms::DoInstructionHashMatch()
{
    vector<BasicBlockMatch> basicBlockMatchList;

    for (vector<unsigned char> hash : m_psrcInstructionHash->GetUniqueHashes())
    {
        vector<va_t> addresses = m_ptargetInstructionHash->GetHashMatches(hash);
        if (addresses.size() == 1)
        {
            BasicBlockMatch basicBlockMatch;
            memset(&basicBlockMatch, 0, sizeof(BasicBlockMatch));
            basicBlockMatch.Type = INSTRUCTION_HASH_MATCH;
            basicBlockMatch.Source = m_psrcInstructionHash->GetHashMatches(hash)[0];
            basicBlockMatch.Target = addresses[0];
            basicBlockMatch.MatchRate = 100;
            basicBlockMatchList.push_back(basicBlockMatch);
        }
    }

    return basicBlockMatchList;
}

vector<BasicBlockMatch> DiffAlgorithms::DoBlocksInstructionHashMatch(unordered_set<va_t>& sourceBlockAddresses, unordered_set<va_t>& targetBlockAddresses)
{
    vector<BasicBlockMatch> matcDataList;
    unordered_set<va_t> targetBlockAddressSet;

    for (va_t address : targetBlockAddresses)
    {
        targetBlockAddressSet.insert(address);
    }

    for (va_t sourceAddress : sourceBlockAddresses)
    {
        vector<unsigned char> instructionHash = m_psrcInstructionHash->GetInstructionHash(sourceAddress);
        vector<va_t> targetAddresses;

        for (va_t targetAddress : m_ptargetInstructionHash->GetHashMatches(instructionHash))
        {
            if (targetBlockAddressSet.find(targetAddress) == targetBlockAddressSet.end())
            {
                continue;
            }

            targetAddresses.push_back(targetAddress);
        }

        if (targetAddresses.size() == 1)
        {
            BasicBlockMatch basicBlockMatch;
            memset(&basicBlockMatch, 0, sizeof(BasicBlockMatch));
            basicBlockMatch.Type = INSTRUCTION_HASH_INSIDE_FUNCTION_MATCH;
            basicBlockMatch.Source = sourceAddress;
            basicBlockMatch.Target = targetAddresses[0];
            basicBlockMatch.MatchRate = 100;
            matcDataList.push_back(basicBlockMatch);
        }
    }

    return matcDataList;
}

BasicBlockMatchCombinations* DiffAlgorithms::GenerateBasicBlockMatchCombinations(vector<BasicBlockMatch> basicBlockMatchList)
{
    unordered_map<va_t, vector<BasicBlockMatch>> matchMap;
    for (BasicBlockMatch basicBlockMatch : basicBlockMatchList)
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format("%x-%x: %d%%") % basicBlockMatch.Source % basicBlockMatch.Target % basicBlockMatch.MatchRate;
        unordered_map<va_t, vector<BasicBlockMatch>>::iterator it = matchMap.find(basicBlockMatch.Source);
        if (it == matchMap.end())
        {
            vector<BasicBlockMatch> basicBlockMatchlist;
            basicBlockMatchlist.push_back(basicBlockMatch);
            matchMap.insert(pair<va_t, vector<BasicBlockMatch>>(basicBlockMatch.Source, basicBlockMatchlist));
        }
        else
        {
            bool isNew = true;
            for (BasicBlockMatch basicBlockMatch2 : it->second)
            {
                if (basicBlockMatch.Source == basicBlockMatch2.Source && basicBlockMatch.Target == basicBlockMatch2.Target)
                {
                    isNew = false;
                    break;
                }
            }

            if (isNew)
            {
                it->second.push_back(basicBlockMatch);
            }
        }
    }

    BasicBlockMatchCombinations* p_basicBlockMatchCombinations = new BasicBlockMatchCombinations();

    if (matchMap.empty())
    {
        return p_basicBlockMatchCombinations;
    }

    for (auto& val : matchMap)
    {
        p_basicBlockMatchCombinations->AddCombinations(val.first, val.second);
    }
    return p_basicBlockMatchCombinations;
}

vector<BasicBlockMatchCombination*> DiffAlgorithms::GetBasicBlockMatchCombinations(vector<BasicBlockMatch> basicBlockMatchList)
{
    BasicBlockMatchCombinations* p_basicBlockMatchCombinations = GenerateBasicBlockMatchCombinations(basicBlockMatchList);
    return p_basicBlockMatchCombinations->GetTopMatches();
}

int DiffAlgorithms::GetMatchRate(va_t source, va_t target)
{
    unordered_map<va_t, unordered_map<va_t, int>>::iterator it = m_matchRateCache.find(source);

    if (it == m_matchRateCache.end())
    {
        unordered_map<va_t, int> it2;
        pair<unordered_map<va_t, unordered_map<va_t, int>>::iterator, bool > result = m_matchRateCache.insert(pair<va_t, unordered_map<va_t, int>>(source, it2));
        it = result.first;
    }
    else
    {
        unordered_map<va_t, int>::iterator it2 = it->second.find(target);
        if (it2 != it->second.end())
        {
            return it2->second;
        }
    }

    int matchRate = GetInstructionHashMatchRate(m_psrcInstructionHash->GetInstructionHash(source), m_ptargetInstructionHash->GetInstructionHash(target));
    it->second.insert(pair<va_t, int>(target, matchRate));
    return matchRate;
}

vector<BasicBlockMatch> DiffAlgorithms::DoControlFlowMatch(va_t sourceAddress, va_t targetAddress, int matchType)
{
    vector<BasicBlockMatch> matches;
    vector<va_t> sourceAddresses = m_psrcBasicBlocks->GetCodeReferences(sourceAddress, matchType);
    vector<va_t> targetAddresses = m_ptargetBasicBlocks->GetCodeReferences(targetAddress, matchType);

    if (matchType != CREF_FROM || (sourceAddresses.size() <= 2 && targetAddresses.size() <= 2))
    {
        for (int i = 0; i < sourceAddresses.size(); i++)
        {
            int matchedIndex = -1;
            int maxMatchRate = 0;
            int maxMatchCount = 0;
            for (int j = 0; j < targetAddresses.size(); j++)
            {
                int matchRate = GetMatchRate(sourceAddresses[i], targetAddresses[j]);
                if (maxMatchRate == matchRate)
                {
                    maxMatchCount++;
                }
                else if (maxMatchRate < matchRate)
                {
                    matchedIndex = j;
                    maxMatchRate = matchRate;
                    maxMatchCount = 1;
                }
            }

            if (maxMatchRate > 0 && maxMatchCount == 1)
            {
                BasicBlockMatch basicBlockMatch;
                basicBlockMatch.Type = CONTROLFLOW_MATCH;
                basicBlockMatch.SourceParent = sourceAddress;
                basicBlockMatch.TargetParent = targetAddress;
                basicBlockMatch.Source = sourceAddresses[i];
                basicBlockMatch.Target = targetAddresses[matchedIndex];
                basicBlockMatch.MatchRate = maxMatchRate;
                matches.push_back(basicBlockMatch);

                BOOST_LOG_TRIVIAL(debug) << boost::format("DiffAlgorithms::DoControlFlowMatch: Max match - %x - %x -> %x - %x MatchRate: %d") %
                    sourceAddress % targetAddress % sourceAddresses[i] % targetAddresses[matchedIndex] % maxMatchRate;            
            }
        }
    }

    if (matchType == CREF_FROM && matches.size() == 0 && sourceAddresses.size() == targetAddresses.size())
    {
        for (int i = 0; i < sourceAddresses.size(); i++)
        {
            BasicBlockMatch basicBlockMatch;
            memset(&basicBlockMatch, 0, sizeof(BasicBlockMatch));
            basicBlockMatch.Type = CONTROLFLOW_MATCH;
            basicBlockMatch.SourceParent = sourceAddress;
            basicBlockMatch.TargetParent = targetAddress;
            basicBlockMatch.Source = sourceAddresses[i];
            basicBlockMatch.Target = targetAddresses[i];
            basicBlockMatch.MatchRate = GetMatchRate(sourceAddresses[i], targetAddresses[i]);
            matches.push_back(basicBlockMatch);

            BOOST_LOG_TRIVIAL(debug) << boost::format("DiffAlgorithms::DoControlFlowMatch: Same Size Match - %x - %x -> %x - %x MatchRate: %d") %
                sourceAddress % targetAddress % sourceAddresses[i] % targetAddresses[i] % basicBlockMatch.MatchRate ;            
        }
    }

    return matches;
}

vector<BasicBlockMatchCombination*> DiffAlgorithms::DoControlFlowMatches(vector<AddressPair> addressPairs, int matchType)
{
    int processed_count = 0;
    vector<BasicBlockMatch> controlFlowMatches;

    for (AddressPair addressPair : addressPairs)
    {
        vector<BasicBlockMatch> newControlFlowMatches = DiffAlgorithms::DoControlFlowMatch(addressPair.SourceAddress, addressPair.TargetAddress, matchType);
        controlFlowMatches.insert(controlFlowMatches.end(), newControlFlowMatches.begin(), newControlFlowMatches.end());
    }

    return GetBasicBlockMatchCombinations(controlFlowMatches);
}

string DiffAlgorithms::GetMatchTypeStr(int Type)
{
    if (Type < sizeof(BasicBlockMatchTypeStr) / sizeof(BasicBlockMatchTypeStr[0]))
    {
        return BasicBlockMatchTypeStr[Type];
    }
    return "Unknown";
}
