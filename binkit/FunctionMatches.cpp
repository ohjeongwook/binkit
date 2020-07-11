#include "FunctionMatches.h"
#include "DiffAlgorithms.h"

FunctionMatches::FunctionMatches(Binary& sourceBinary, Binary& targetBinary)
{
	m_sourceBinary = sourceBinary;
	m_targetBinary = targetBinary;
}

void FunctionMatches::Add(va_t sourceFunctionAddress, va_t targetFunctionAddress, MatchData matchData)
{
	unordered_map<va_t, TargetToMatchDataListMap>::iterator it = m_functionMatches.find(sourceFunctionAddress);
	if (it == m_functionMatches.end())
	{
		TargetToMatchDataListMap targetToMatchDataList;
		vector<MatchData> matchDataList;
		matchDataList.push_back(matchData);
		targetToMatchDataList.insert(pair<va_t, vector<MatchData>>(targetFunctionAddress, matchDataList));
		m_functionMatches.insert(pair<va_t, TargetToMatchDataListMap>(sourceFunctionAddress, targetToMatchDataList));
	}
	else
	{
		TargetToMatchDataListMap::iterator targetToMatchDataListMapit = it->second.find(targetFunctionAddress);

		if (targetToMatchDataListMapit == it->second.end())
		{
			vector<MatchData> matchDataList;
			matchDataList.push_back(matchData);
			it->second.insert(pair<va_t, vector<MatchData>>(targetFunctionAddress, matchDataList));
		}
		else
		{
			bool isNewMatchData = true;
			for (MatchData currentMatchData : targetToMatchDataListMapit->second)
			{
				if (matchData.Source == currentMatchData.Source && matchData.Target == currentMatchData.Target)
				{
					isNewMatchData = false;
					break;
				}
			}

			if (isNewMatchData)
			{
				targetToMatchDataListMapit->second.push_back(matchData);
			}
		}
	}
}

void FunctionMatches::Add(va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<MatchData> matchDataList)
{
	for (MatchData matchData : matchDataList)
	{
		Add(sourceFunctionAddress, targetFunctionAddress, matchData);
	}
}

void FunctionMatches::Print()
{
	for (auto& val : m_functionMatches)
	{
		va_t sourceFunctionAddress = val.first;
		for (auto& val2 : val.second)
		{
			va_t targetFunctionAddress = val2.first;

			printf("==========================================\n");
			printf("Function: %x - %x\n", sourceFunctionAddress, targetFunctionAddress);
			for (MatchData matchData : val2.second)
			{
				printf("\tMatch: %x-%x %d\n", matchData.Source, matchData.Target, matchData.MatchRate);
			}
		}
	}
}

vector<FunctionMatch> FunctionMatches::GetMatches()
{
	vector<FunctionMatch> functionMatchDataList;

	for (auto& val : m_functionMatches)
	{
		va_t sourceFunctionAddress = val.first;
		for (auto& val2 : val.second)
		{
			FunctionMatch functionMatch;
			functionMatch.SourceFunction = sourceFunctionAddress;
			functionMatch.TargetFunction = val2.first;
			functionMatch.MatchDataList = val2.second;
			functionMatchDataList.push_back(functionMatch);
		}
	}

	return functionMatchDataList;
}

void FunctionMatches::AddMatches(vector<MatchData> currentMatchDataList)
{
	for (MatchData matchData : currentMatchDataList)
	{
		va_t sourceFunctionAddress;
		Function* p_src_function = m_sourceBinary.GetFunction(matchData.Source);
		Function* p_target_function = m_targetBinary.GetFunction(matchData.Target);

		if (p_src_function && p_target_function)
		{
			Add(p_src_function->GetAddress(), p_target_function->GetAddress(), matchData);
		}
	}
}

void FunctionMatches::DoInstructionHashMatch()
{
	DiffAlgorithms* p_diffAlgorithms = new DiffAlgorithms(m_sourceBinary, m_targetBinary);

	for (auto& val : m_functionMatches)
	{
		va_t sourceFunctionAddress = val.first;
		vector<va_t> sourceFunctionAddresses = m_sourceBinary.GetFunction(sourceFunctionAddress)->GetBasicBlocks();
		for (auto& val2 : val.second)
		{
			va_t targetFunctionAddress = val2.first;

			vector<va_t> targetFunctionAddresses = m_targetBinary.GetFunction(targetFunctionAddress)->GetBasicBlocks();
			vector<MatchData> functionInstructionHashMatches = p_diffAlgorithms->DoInstructionHashMatchInBlocks(sourceFunctionAddresses, targetFunctionAddresses);
			Add(sourceFunctionAddress, targetFunctionAddress, functionInstructionHashMatches);
		}
	}
}

void FunctionMatches::DoControlFlowMatch()
{
	DiffAlgorithms* p_diffAlgorithms = new DiffAlgorithms(m_sourceBinary, m_targetBinary);

	for (auto& val : m_functionMatches)
	{
		va_t sourceFunctionAddress = val.first;
		for (auto& val2 : val.second)
		{
			va_t targetFunctionAddress = val2.first;
			for (MatchData matchData : val2.second)
			{
				vector<MatchData> functionControlFlowMatches = p_diffAlgorithms->DoControlFlowMatch(matchData.Source, matchData.Target, CREF_FROM);
				Add(sourceFunctionAddress, targetFunctionAddress, functionControlFlowMatches);
			}
		}
	}
}
