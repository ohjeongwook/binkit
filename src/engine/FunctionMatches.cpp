#include "FunctionMatches.h"
#include "DiffAlgorithms.h"

FunctionMatches::FunctionMatches(Binary& sourceBinary, Binary& targetBinary)
{
	m_sourceBinary = sourceBinary;
	m_targetBinary = targetBinary;
	m_matchSequence = 1;
	m_pdiffAlgorithms = new DiffAlgorithms(m_sourceBinary, m_targetBinary);
}

void FunctionMatches::AddMatchData(va_t sourceFunctionAddress, va_t targetFunctionAddress, MatchData matchData)
{
	matchData.MatchSequence = m_matchSequence;
	unordered_map<va_t, unordered_map<va_t, vector<MatchData*>>>::iterator it = m_functionMatches.find(sourceFunctionAddress);
	if (it == m_functionMatches.end())
	{
		std::pair<unordered_map<va_t, unordered_map<va_t, vector<MatchData*>>>::iterator, bool > result = m_functionMatches.insert(pair<va_t, unordered_map<va_t, vector<MatchData*>>>(sourceFunctionAddress, {}));
		it = result.first;
	}

	unordered_map<va_t, vector<MatchData*>>::iterator targetToMatchDataListMapit = it->second.find(targetFunctionAddress);
	if (targetToMatchDataListMapit == it->second.end())
	{
		std::pair<unordered_map<va_t, vector<MatchData*>>::iterator, bool > result = it->second.insert(pair<va_t, vector<MatchData *>>(targetFunctionAddress, {}));
		targetToMatchDataListMapit = result.first;
	}

	bool addMatchData = true;
	for (auto it = targetToMatchDataListMapit->second.begin(); it != targetToMatchDataListMapit->second.end(); it++)
	{
		MatchData* p_currentMatchData = (*it);
		if (matchData.Source == p_currentMatchData->Source && matchData.Target == p_currentMatchData->Target)
		{
			addMatchData = false;
			break;
		}

		if (matchData.Source == p_currentMatchData->Source || matchData.Target == p_currentMatchData->Target)
		{
			if (matchData.MatchRate > p_currentMatchData->MatchRate)
			{
				it = targetToMatchDataListMapit->second.erase(it);
				break;
			}
			else
			{
				addMatchData = false;
			}
		}
	}

	if (addMatchData)
	{
		MatchData* p_matchData = new MatchData();
		memcpy(p_matchData, &matchData, sizeof(matchData));
		targetToMatchDataListMapit->second.push_back(p_matchData);
	}
}

void FunctionMatches::AddMatchDataList(va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<MatchData> matchDataList)
{
	for (MatchData matchData : matchDataList)
	{
		AddMatchData(sourceFunctionAddress, targetFunctionAddress, matchData);
	}
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
		unordered_map<va_t, unordered_map<va_t, vector<MatchData*>>>::iterator it = m_functionMatches.find(address);
		if (it != m_functionMatches.end())
		{
			va_t sourceFunctionAddress = it->first;
			for (auto& val2 : it->second)
			{
				vector<MatchData> fullMatchDataList;
				va_t targetFunctionAddress = val2.first;
				for (MatchData *p_matchData : val2.second)
				{
					vector<MatchData> matchDataList = m_pdiffAlgorithms->DoControlFlowMatch(p_matchData->Source, p_matchData->Target, CREF_FROM);
					fullMatchDataList.insert(fullMatchDataList.end(), matchDataList.begin(), matchDataList.end());
				}
				AddMatchDataList(sourceFunctionAddress, targetFunctionAddress, fullMatchDataList);
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
				vector<MatchData> fullMatchDataList;
				va_t targetFunctionAddress = val2.first;

				for (MatchData *p_matchData : val2.second)
				{
					vector<MatchData> matchDataList = m_pdiffAlgorithms->DoControlFlowMatch(p_matchData->Source, p_matchData->Target, CREF_FROM);
					fullMatchDataList.insert(fullMatchDataList.end(), matchDataList.begin(), matchDataList.end());
				}
				AddMatchDataList(sourceFunctionAddress, targetFunctionAddress, fullMatchDataList);
			}
		}
	}

	m_matchSequence++;

	return m_matchSequence - 1;
}

void FunctionMatches::RemoveMatches(int matchSequence)
{
	for (auto& val : m_functionMatches)
	{
		for (auto& val2 : val.second)
		{
			for (auto it = val2.second.begin(); it != val2.second.end(); )
			{
				if ((*it)->MatchSequence == matchSequence)
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
