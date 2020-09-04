#pragma once
#include <unordered_map>

#include "Binary.h"
#include "BasicBlocks.h"

using namespace std;

struct FunctionMatch
{
    va_t SourceFunction;
    va_t TargetFunction;
    vector<BasicBlockMatch *> BasicBlockMatchList;
};

class DiffAlgorithms;

class FunctionMatches
{
private:
    Binary* m_sourceBinary;
    Binary* m_targetBinary;
    DiffAlgorithms* m_pdiffAlgorithms;
    int m_matchSequence;
    unordered_map<va_t, unordered_map<va_t, vector<BasicBlockMatch*>>> m_functionMatches;
    void AddBasicBlockMatches(va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<BasicBlockMatch> basicBlockMatchList);

public:
    FunctionMatches(Binary* p_sourceBinary, Binary* p_targetBinary);

    void AddMatches(vector<BasicBlockMatch> currentBasicBlockMatchList);
    void AddBasicBlockMatch(va_t sourceFunctionAddress, va_t targetFunctionAddress, BasicBlockMatch basicBlockMatch);

    int DoFunctionInstructionHashMatch(va_t sourceFunctionAddress, va_t targetFunctionAddress);
    int DoInstructionHashMatch();
    int DoControlFlowMatch(va_t address = 0);
    void RemoveMatches(int matchSequence);

    vector<FunctionMatch> GetMatches();
};
