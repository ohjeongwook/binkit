#pragma once
#include <unordered_map>

#include "Binary.h"
#include "Functions.h"
#include "BasicBlocks.h"
#include "Log.h"

using namespace std;

typedef unordered_map<va_t, vector<MatchData>> TargetToMatchDataListMap;

struct FunctionMatch
{
	va_t SourceFunction;
	va_t TargetFunction;
	vector<MatchData> MatchDataList;
};

class FunctionMatches
{
private:
	Binary m_sourceBinary;
	Binary m_targetBinary;
	Functions* m_psourceFunctions;
	Functions* m_ptargetFunctions;
	unordered_map<va_t, TargetToMatchDataListMap> m_functionMatches;
	void Add(va_t sourceFunctionAddress, va_t targetFunctionAddress, MatchData matchData);
	void Add(va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<MatchData> matchDataList);

public:
	FunctionMatches(Binary& sourceBinary, Binary& targetBinary);

	void AddMatches(vector<MatchData> currentMatchDataList);
	void Print();
	vector<FunctionMatch> GetMatches();

	void DoInstructionHashMatch();
	void DoControlFlowMatch();
};
