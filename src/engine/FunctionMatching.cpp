#include "FunctionMatching.h"
#include "DiffAlgorithms.h"

FunctionMatching::FunctionMatching(Binary* p_sourceBinary, Binary* p_targetBinary)
{
    m_sourceBinary = p_sourceBinary;
    m_targetBinary = p_targetBinary;
    m_matchSequence = 1;
    m_pdiffAlgorithms = new DiffAlgorithms(p_sourceBinary, p_targetBinary);
}

void FunctionMatching::AddMatches(vector<BasicBlockMatch> basicBlockMatches)
{
    BOOST_LOG_TRIVIAL(debug) << boost::format("FunctionMatching::AddMatches count: %d") % basicBlockMatches.size();
    for (BasicBlockMatch basicBlockMatch : basicBlockMatches)
    {
        for(Function* pSrcFunction : m_sourceBinary->GetFunction(basicBlockMatch.Source))
        {
            for(Function* pTargetFunction : m_targetBinary->GetFunction(basicBlockMatch.Target))
            {
                BOOST_LOG_TRIVIAL(debug) << boost::format("FunctionMatching::AddMatches %s (%x) - %s (%x) %x - %x (%d)") % 
                    pSrcFunction->GetSymbol() % pSrcFunction->GetAddress() %
                    pTargetFunction->GetSymbol() % pTargetFunction->GetAddress() %
                    basicBlockMatch.Source % basicBlockMatch.Target % basicBlockMatch.MatchRate;
                m_functionMatchList.Add(pSrcFunction->GetAddress(), pTargetFunction->GetAddress(), basicBlockMatch);
            }
        }
    }
}

vector<FunctionMatch> FunctionMatching::GetMatches()
{
    return m_functionMatchList.GetMatches();
}

void FunctionMatching::RemoveMatches(int matchSequence)
{
    m_functionMatchList.RemoveMatches(matchSequence);
}

int FunctionMatching::DoFunctionInstructionHashMatch(va_t srcFunctionAddress, va_t targetFunctionAddress)
{
    Function *pSrcFunction = m_sourceBinary->GetFunctionByStartAddress(srcFunctionAddress);
    Function *pTargetFunction = m_targetBinary->GetFunctionByStartAddress(targetFunctionAddress);
    unordered_set<va_t> srcFunctionAddresses = pSrcFunction->GetBasicBlocks();
    unordered_set<va_t> targetFunctionAddresses = pTargetFunction->GetBasicBlocks();
    vector<BasicBlockMatch> basicBlockMatches = m_pdiffAlgorithms->DoBlocksInstructionHashMatch(srcFunctionAddresses, targetFunctionAddresses);
    m_functionMatchList.Add(srcFunctionAddress, targetFunctionAddress, basicBlockMatches);
    return basicBlockMatches.size();
}

int FunctionMatching::DoInstructionHashMatch()
{
    int matchCount = 0;
    if (m_functionMatchList.GetSize() == 0)
    {
        vector<BasicBlockMatch> basicBlocksMatches = m_pdiffAlgorithms->DoInstructionHashMatch();
        AddMatches(basicBlocksMatches);
    }
    else
    {
        for(auto & val : m_functionMatchList.GetFunctionAddresses())
        {
            va_t srcFunctionAddress = val.first;
            va_t targetFunctionAddress = val.second;
            Function* pSrcFunction = m_sourceBinary->GetFunctionByStartAddress(srcFunctionAddress);
            Function* targetFunction = m_targetBinary->GetFunctionByStartAddress(targetFunctionAddress);
            unordered_set<va_t> srcFunctionAddresses = pSrcFunction->GetBasicBlocks();
            unordered_set<va_t> targetFunctionAddresses = targetFunction->GetBasicBlocks();
            vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoBlocksInstructionHashMatch(srcFunctionAddresses, targetFunctionAddresses);
            matchCount += basicBlockMatchList.size();
            m_functionMatchList.Add(srcFunctionAddress, targetFunctionAddress, basicBlockMatchList);
        }
    }
    m_matchSequence++;
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

                            if (m_functionMatchList.Add(pSrcFunction->GetAddress(), pTargetFunction->GetAddress(), basicBlockMatch), "      ")
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

    m_matchSequence++;
    BOOST_LOG_TRIVIAL(debug) << boost::format("DoControlFlowMatch matchType: %x matchCount: %d") % matchType % matchCount;
    return matchCount;
}
