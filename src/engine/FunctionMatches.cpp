#include "FunctionMatches.h"
#include "DiffAlgorithms.h"

FunctionMatches::FunctionMatches(Binary* p_sourceBinary, Binary* p_targetBinary)
{
    m_sourceBinary = p_sourceBinary;
    m_targetBinary = p_targetBinary;
    m_matchSequence = 1;
    m_pdiffAlgorithms = new DiffAlgorithms(p_sourceBinary, p_targetBinary);
}

void FunctionMatches::AddMatches(vector<BasicBlockMatch> currentBasicBlockMatchList)
{
    for (BasicBlockMatch basicBlockMatch : currentBasicBlockMatchList)
    {
        Function* p_src_function = m_sourceBinary->GetFunction(basicBlockMatch.Source);
        Function* p_target_function = m_targetBinary->GetFunction(basicBlockMatch.Target);

        if (p_src_function && p_target_function)
        {
            m_functionMatchList.Add(p_src_function->GetAddress(), p_target_function->GetAddress(), basicBlockMatch);
        }
    }
}

int FunctionMatches::DoFunctionInstructionHashMatch(va_t sourceFunctionAddress, va_t targetFunctionAddress)
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

int FunctionMatches::DoInstructionHashMatch()
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

int FunctionMatches::DoControlFlowMatch(va_t address, int matchType)
{
    int matchCount = 0;
    if (address != 0)
    {
        for(FunctionMatch & functionMatch : m_functionMatchList.GetFunctionMatches(address))
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

        for(FunctionMatch & functionMatch : m_functionMatchList.GetFunctionMatches(address))
        {
            vector<BasicBlockMatch> fullBasicBlockMatchList;
            for (BasicBlockMatch *p_basicBlockMatch : functionMatch.BasicBlockMatchList)
            {
                if (p_basicBlockMatch->Flags & matchMask)
                {
                    continue;
                }
                // BOOST_LOG_TRIVIAL(debug) << boost::format("Source: %x Target: %x") % p_basicBlockMatch->Source % p_basicBlockMatch->Target;
                vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoControlFlowMatch(p_basicBlockMatch->Source, p_basicBlockMatch->Target, matchType);
                matchCount += basicBlockMatchList.size();
                // BOOST_LOG_TRIVIAL(debug) << boost::format("\tmatchCount: %x") % matchCount;
                fullBasicBlockMatchList.insert(fullBasicBlockMatchList.end(), basicBlockMatchList.begin(), basicBlockMatchList.end());
                p_basicBlockMatch->Flags |= matchMask;
            }
            if (fullBasicBlockMatchList.size() > 0)
            {
                BOOST_LOG_TRIVIAL(debug) << boost::format("\tAddBasicBlockMatches: fullBasicBlockMatchList.size(): %x") % fullBasicBlockMatchList.size();
                m_functionMatchList.Add(functionMatch.SourceFunction, functionMatch.TargetFunction, fullBasicBlockMatchList);
            }
        }
    }

    m_matchSequence++;

    return matchCount;
}
