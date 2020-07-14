#include "FunctionMatches.h"
#include "DiffAlgorithms.h"

FunctionMatches::FunctionMatches(Binary& sourceBinary, Binary& targetBinary)
{
	m_sourceBinary = sourceBinary;
	m_targetBinary = targetBinary;
	m_matchSequence = 0;
	m_pdiffAlgorithms = new DiffAlgorithms(m_sourceBinary, m_targetBinary);
}

void FunctionMatches::AddMatchData(va_t sourceFunctionAddress, va_t targetFunctionAddress, MatchData matchData)
{
	matchData.MatchSequence = m_matchSequence;
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

void FunctionMatches::AddMatchDataList(va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<MatchData> matchDataList)
{
	for (MatchData matchData : matchDataList)
	{
		AddMatchData(sourceFunctionAddress, targetFunctionAddress, matchData);
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
				printf("\tMatch: %x-%x %d (MatchSequence: %d)\n", matchData.Source, matchData.Target, matchData.MatchRate, matchData.MatchSequence);
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
			AddMatchData(p_src_function->GetAddress(), p_target_function->GetAddress(), matchData);
		}
	}
}

int FunctionMatches::DoInstructionHashMatch()
{
	for (auto& val : m_functionMatches)
	{
		va_t sourceFunctionAddress = val.first;
		vector<va_t> sourceFunctionAddresses = m_sourceBinary.GetFunction(sourceFunctionAddress)->GetBasicBlocks();
		for (auto& val2 : val.second)
		{
			va_t targetFunctionAddress = val2.first;

			vector<va_t> targetFunctionAddresses = m_targetBinary.GetFunction(targetFunctionAddress)->GetBasicBlocks();
			vector<MatchData> matchDataList = m_pdiffAlgorithms->DoBlocksInstructionHashMatch(sourceFunctionAddresses, targetFunctionAddresses);
			AddMatchDataList(sourceFunctionAddress, targetFunctionAddress, matchDataList);
		}
	}

	m_matchSequence++;

	return m_matchSequence - 1;
}

int FunctionMatches::DoControlFlowMatch(va_t address)
{
	if (address != 0)
	{
		unordered_map<va_t, TargetToMatchDataListMap>::iterator it = m_functionMatches.find(address);
		if (it != m_functionMatches.end())
		{
			va_t sourceFunctionAddress = it->first;
			for (auto& val2 : it->second)
			{
				va_t targetFunctionAddress = val2.first;
				for (MatchData matchData : val2.second)
				{
					vector<MatchData> matchDataList = m_pdiffAlgorithms->DoControlFlowMatch(matchData.Source, matchData.Target, CREF_FROM);
					AddMatchDataList(sourceFunctionAddress, targetFunctionAddress, matchDataList);
				}
			}
		}
	}
	else
	{

		for (auto& val : m_functionMatches)
		{
			va_t sourceFunctionAddress = val.first;
			for (auto& val2 : val.second)
			{
				va_t targetFunctionAddress = val2.first;
				for (MatchData matchData : val2.second)
				{
					vector<MatchData> matchDataList = m_pdiffAlgorithms->DoControlFlowMatch(matchData.Source, matchData.Target, CREF_FROM);
					AddMatchDataList(sourceFunctionAddress, targetFunctionAddress, matchDataList);
				}
			}
		}
	}

	m_matchSequence++;

	return m_matchSequence - 1;
}

void FunctionMatches::RemoveMatches(int matchSequence)
{
	printf("RemoveMatches %d\n", matchSequence);
	for (auto& val : m_functionMatches)
	{
		va_t sourceFunctionAddress = val.first;
		for (auto& val2 : val.second)
		{
			va_t targetFunctionAddress = val2.first;
			for (auto it = val2.second.begin(); it != val2.second.end(); ) {
				if (it->MatchSequence == matchSequence)
				{
					it = val2.second.erase(it);
				}
				else {
					++it;
				}
			}
		}
	}
}
