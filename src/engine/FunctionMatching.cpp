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
    BOOST_LOG_TRIVIAL(debug) << boost::format("AddMatches count: %d") % basicBlockMatches.size();
    for (BasicBlockMatch basicBlockMatch : basicBlockMatches)
    {
        Function* pSrcFunction = m_sourceBinary->GetFunction(basicBlockMatch.Source);
        Function* pTargetFunction = m_targetBinary->GetFunction(basicBlockMatch.Target);

        BOOST_LOG_TRIVIAL(debug) << boost::format("pSrcFunction: %p pTargetFunction: %p") % pSrcFunction % pTargetFunction;
        if (pSrcFunction && pTargetFunction)
        {
            m_functionMatchList.Add(pSrcFunction->GetAddress(), pTargetFunction->GetAddress(), basicBlockMatch);
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

int FunctionMatching::DoFunctionInstructionHashMatch(va_t sourceFunctionAddress, va_t targetFunctionAddress)
{
    Function *sourceFunction = m_sourceBinary->GetFunction(sourceFunctionAddress);
    Function *targetFunction = m_targetBinary->GetFunction(targetFunctionAddress);

    if (sourceFunction && targetFunction)
    {
        unordered_set<va_t> sourceFunctionAddresses = sourceFunction->GetBasicBlocks();
        unordered_set<va_t> targetFunctionAddresses = targetFunction->GetBasicBlocks();
        vector<BasicBlockMatch> basicBlockMatches = m_pdiffAlgorithms->DoBlocksInstructionHashMatch(sourceFunctionAddresses, targetFunctionAddresses);
        m_functionMatchList.Add(sourceFunctionAddress, targetFunctionAddress, basicBlockMatches);
        return basicBlockMatches.size();
    }
    return 0;
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
            va_t sourceFunctionAddress = val.first;
            va_t targetFunctionAddress = val.second;
            unordered_set<va_t> sourceFunctionAddresses = m_sourceBinary->GetFunction(sourceFunctionAddress)->GetBasicBlocks();
            unordered_set<va_t> targetFunctionAddresses = m_targetBinary->GetFunction(targetFunctionAddress)->GetBasicBlocks();
            vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoBlocksInstructionHashMatch(sourceFunctionAddresses, targetFunctionAddresses);
            matchCount += basicBlockMatchList.size();
            m_functionMatchList.Add(sourceFunctionAddress, targetFunctionAddress, basicBlockMatchList);
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
            vector<BasicBlockMatch> fullBasicBlockMatchList;                
            for (BasicBlockMatch *p_basicBlockMatch : functionMatch.BasicBlockMatchList)
            {
                vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoControlFlowMatch(p_basicBlockMatch->Source, p_basicBlockMatch->Target, matchType);
                fullBasicBlockMatchList.insert(fullBasicBlockMatchList.end(), basicBlockMatchList.begin(), basicBlockMatchList.end());
            }
            m_functionMatchList.Add(functionMatch.SourceFunction, functionMatch.TargetFunction, fullBasicBlockMatchList);
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

        BOOST_LOG_TRIVIAL(debug) << boost::format("matchType: %x matchMask: %x") % matchType % matchMask;

        for(FunctionMatch & functionMatch : m_functionMatchList.GetMatches(matchMask))
        {
            vector<BasicBlockMatch> fullBasicBlockMatchList;
            BOOST_LOG_TRIVIAL(debug) << boost::format("Function Source: %x Target: %x") % functionMatch.SourceFunction % functionMatch.TargetFunction;
            for (BasicBlockMatch *p_basicBlockMatch : functionMatch.BasicBlockMatchList)
            {
                BOOST_LOG_TRIVIAL(debug) << boost::format("   Source: %x Target: %x") % p_basicBlockMatch->Source % p_basicBlockMatch->Target;
                vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoControlFlowMatch(p_basicBlockMatch->Source, p_basicBlockMatch->Target, matchType);
                BOOST_LOG_TRIVIAL(debug) << boost::format("AddBasicBlockMatches: basicBlockMatchList.size(): %x") % basicBlockMatchList.size();

                for (BasicBlockMatch basicBlockMatch : basicBlockMatchList)
                {
                    Function* pSrcFunction = m_sourceBinary->GetFunction(basicBlockMatch.Source);
                    Function* pTargetFunction = m_targetBinary->GetFunction(basicBlockMatch.Target);

                    if (pSrcFunction && pTargetFunction)
                    {
                        if (m_functionMatchList.Add(pSrcFunction->GetAddress(), pTargetFunction->GetAddress(), basicBlockMatch))
                        {
                            matchCount++;
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
