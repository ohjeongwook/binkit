#include "FunctionMatching.h"
#include "DiffAlgorithms.h"
#include <iostream>
#include <iomanip>
#include <sstream>

FunctionMatching::FunctionMatching(Binary* p_sourceBinary, Binary* p_targetBinary)
{
    m_sourceBinary = p_sourceBinary;
    m_targetBinary = p_targetBinary;
    m_pdiffAlgorithms = new DiffAlgorithms(p_sourceBinary, p_targetBinary);
}

vector<FunctionMatch> FunctionMatching::GetMatches()
{
    return m_functionMatchList.GetMatches();
}

void FunctionMatching::RemoveMatches(int matchSequence)
{
    m_functionMatchList.RemoveMatches(matchSequence);
}

int FunctionMatching::DoInstructionHashMatch()
{
    int matchCount = 0;

    BOOST_LOG_TRIVIAL(debug) << boost::format("FunctionMatching::DoInstructionHashMatch m_functionMatchList.GetSize(): %d") % m_functionMatchList.GetSize();
    if (m_functionMatchList.GetSize() == 0)
    {
        for (BasicBlockMatch basicBlockMatch : m_pdiffAlgorithms->DoInstructionHashMatch())
        {
            for(Function* pSrcFunction : m_sourceBinary->GetFunction(basicBlockMatch.Source))
            {
                for(Function* pTargetFunction : m_targetBinary->GetFunction(basicBlockMatch.Target))
                {
                    BOOST_LOG_TRIVIAL(debug) << boost::format("FunctionMatching::DoInstructionHashMatch %s (%x) - %s (%x) %x - %x (%d)") % 
                        pSrcFunction->GetSymbol() % pSrcFunction->GetAddress() %
                        pTargetFunction->GetSymbol() % pTargetFunction->GetAddress() %
                        basicBlockMatch.Source % basicBlockMatch.Target % basicBlockMatch.MatchRate;
                    matchCount += m_functionMatchList.Add(pSrcFunction->GetAddress(), pTargetFunction->GetAddress(), basicBlockMatch, "  ");
                }
            }
        }
    }
    else
    {
        for(auto & val : m_functionMatchList.GetFunctionAddresses())
        {
            Function* pSrcFunction = m_sourceBinary->GetFunctionByStartAddress(val.first);
            unordered_set<va_t> srcFunctionAddresses = pSrcFunction->GetBasicBlocks();

            Function* pTargetFunction = m_targetBinary->GetFunctionByStartAddress(val.second);
            unordered_set<va_t> targetFunctionAddresses = pTargetFunction->GetBasicBlocks();

            for(BasicBlockMatch* p_basicBlockMatch : m_functionMatchList.GetBasicBlockMatches(val.first, val.second))
            {
                srcFunctionAddresses.erase(p_basicBlockMatch->Source);
                targetFunctionAddresses.erase(p_basicBlockMatch->Target);
            }

            if (srcFunctionAddresses.size() == 0 && targetFunctionAddresses.size() == 0)
            {
                continue;
            }

            std::stringstream srcAddressesString("");
            for(va_t address : srcFunctionAddresses)
            {
                srcAddressesString << std::setfill('0') << std::setw(8) << std::hex << address << " ";
            }

            std::stringstream targetAddressesString("");
            for(va_t address : targetFunctionAddresses)
            {
                targetAddressesString << std::setfill('0') << std::setw(8) << std::hex << address << " ";
            }            

            BOOST_LOG_TRIVIAL(debug) << boost::format("FunctionMatching::DoInstructionHashMatch %s (%x) - %s (%x)") % 
                pSrcFunction->GetSymbol() % pSrcFunction->GetAddress() %
                pTargetFunction->GetSymbol() % pTargetFunction->GetAddress();

            BOOST_LOG_TRIVIAL(debug) << boost::format("    > Source Addresses: %s") % srcAddressesString.str().c_str();
            BOOST_LOG_TRIVIAL(debug) << boost::format("    > Target Addresses: %s") % targetAddressesString.str().c_str();
            vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoBlocksInstructionHashMatch(srcFunctionAddresses, targetFunctionAddresses);
            matchCount += m_functionMatchList.Add(val.first, val.second, basicBlockMatchList);
        }
    }
    return matchCount;
}

int FunctionMatching::DoControlFlowMatch(va_t address, int matchType)
{
    int matchCount = 0;
    if (address != 0)
    {
        for(FunctionMatch & functionMatch : m_functionMatchList.GetMatchesByAddress(address))
        {
            for (BasicBlockMatch *p_basicBlockMatch : functionMatch.BasicBlockMatchList)
            {
                vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoControlFlowMatch(p_basicBlockMatch->Source, p_basicBlockMatch->Target, matchType);
                m_functionMatchList.Add(functionMatch.SourceFunction, functionMatch.TargetFunction, basicBlockMatchList);
            }
        }
    }
    else
    {
        int matchMask = 0;
        switch(matchType)
        {
            case CALL:
                matchMask = CALL_MATCH;
                break;            
            case CREF_FROM:
                matchMask = CREF_FROM_MATCH;
                break;            
            case CREF_TO:
                matchMask = CREF_TO_MATCH;
                break;            
            case DREF_FROM:
                matchMask = DREF_FROM_MATCH;
                break;            
            case DREF_TO:
                matchMask = DREF_TO_MATCH;
                break;            
            case CALLED:
                matchMask = CALLED_MATCH;
                break;            
        }

        for(FunctionMatch & functionMatch : m_functionMatchList.GetMatches(matchMask))
        {
            for (BasicBlockMatch *p_basicBlockMatch : functionMatch.BasicBlockMatchList)
            {
                BOOST_LOG_TRIVIAL(debug) << boost::format("* DoControlFlowMatch: %x (%x) %x (%x) matchType: %x") % functionMatch.SourceFunction % p_basicBlockMatch->Source % functionMatch.TargetFunction % p_basicBlockMatch->Target % matchType;
                vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoControlFlowMatch(p_basicBlockMatch->Source, p_basicBlockMatch->Target, matchType);
                for (BasicBlockMatch basicBlockMatch : basicBlockMatchList)
                {
                    BOOST_LOG_TRIVIAL(debug) << boost::format("  - basicBlockMatch: %x %x (MatchRate: %d)") % basicBlockMatch.Source % basicBlockMatch.Target % basicBlockMatch.MatchRate;
                    for(Function* pSrcFunction : m_sourceBinary->GetFunction(basicBlockMatch.Source))
                    {
                        for(Function* pTargetFunction : m_targetBinary->GetFunction(basicBlockMatch.Target))
                        {
                            BOOST_LOG_TRIVIAL(debug) << boost::format("    - basicBlockMatch %s (%x) - %s (%x) (MatchRate: %d)") % 
                                pSrcFunction->GetSymbol() %
                                basicBlockMatch.Source %
                                pTargetFunction->GetSymbol() %                                
                                basicBlockMatch.Target %
                                basicBlockMatch.MatchRate;

                            if (m_functionMatchList.Add(pSrcFunction->GetAddress(), pTargetFunction->GetAddress(), basicBlockMatch, "      "))
                            {
                                matchCount++;
                            }
                        }
                    }
                }
                p_basicBlockMatch->Flags |= matchMask;
            }
        }
    }

    BOOST_LOG_TRIVIAL(debug) << boost::format("DoControlFlowMatch matchType: %x matchCount: %d") % matchType % matchCount;
    return matchCount;
}
