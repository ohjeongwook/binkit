#pragma once
#include <unordered_map>

#include "Binary.h"
#include "BasicBlocks.h"
#include "Log.h"

using namespace std;

struct FunctionMatch
{
	va_t SourceFunction;
	va_t TargetFunction;
	vector<MatchData *> MatchDataList;
};

class DiffAlgorithms;

class FunctionMatches
{
private:
	Binary m_sourceBinary;
	Binary m_targetBinary;
	DiffAlgorithms* m_pdiffAlgorithms;
	int m_matchSequence;
	unordered_map<va_t, unordered_map<va_t, vector<MatchData*>>> m_functionMatches;
	void AddMatchData(va_t sourceFunctionAddress, va_t targetFunctionAddress, MatchData matchData);
	void AddMatchDataList(va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<MatchData> matchDataList);

public:
	FunctionMatches(Binary& sourceBinary, Binary& targetBinary);

	void AddMatches(vector<MatchData> currentMatchDataList);
	void Print();
	vector<FunctionMatch> GetMatches();

	int DoInstructionHashMatch();
	int DoControlFlowMatch(va_t address = 0);
	void RemoveMatches(int matchSequence);
};
