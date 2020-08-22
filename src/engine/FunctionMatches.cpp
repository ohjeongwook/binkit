#include "FunctionMatches.h"
#include "DiffAlgorithms.h"

FunctionMatches::FunctionMatches(Binary* p_sourceBinary, Binary* p_targetBinary)
{
	m_sourceBinary = p_sourceBinary;
	m_targetBinary = p_targetBinary;
	m_matchSequence = 1;
	m_pdiffAlgorithms = new DiffAlgorithms(p_sourceBinary, p_targetBinary);
}

void FunctionMatches::AddBasicBlockMatch(va_t sourceFunctionAddress, va_t targetFunctionAddress, BasicBlockMatch basicBlockMatch)
{
	basicBlockMatch.MatchSequence = m_matchSequence;
	unordered_map<va_t, unordered_map<va_t, vector<BasicBlockMatch*>>>::iterator it = m_functionMatches.find(sourceFunctionAddress);
	if (it == m_functionMatches.end())
	{
		std::pair<unordered_map<va_t, unordered_map<va_t, vector<BasicBlockMatch*>>>::iterator, bool > result = m_functionMatches.insert(pair<va_t, unordered_map<va_t, vector<BasicBlockMatch*>>>(sourceFunctionAddress, {}));
		it = result.first;
	}

	unordered_map<va_t, vector<BasicBlockMatch*>>::iterator targetToBasicBlockMatchListMapit = it->second.find(targetFunctionAddress);
	if (targetToBasicBlockMatchListMapit == it->second.end())
	{
		std::pair<unordered_map<va_t, vector<BasicBlockMatch*>>::iterator, bool > result = it->second.insert(pair<va_t, vector<BasicBlockMatch *>>(targetFunctionAddress, {}));
		targetToBasicBlockMatchListMapit = result.first;
	}

	bool addBasicBlockMatch = true;
	for (auto it = targetToBasicBlockMatchListMapit->second.begin(); it != targetToBasicBlockMatchListMapit->second.end(); it++)
	{
		BasicBlockMatch* p_currentBasicBlockMatch = (*it);
		if (basicBlockMatch.Source == p_currentBasicBlockMatch->Source && basicBlockMatch.Target == p_currentBasicBlockMatch->Target)
		{
			addBasicBlockMatch = false;
			break;
		}

		if (basicBlockMatch.Source == p_currentBasicBlockMatch->Source || basicBlockMatch.Target == p_currentBasicBlockMatch->Target)
		{
			if (basicBlockMatch.MatchRate > p_currentBasicBlockMatch->MatchRate)
			{
				it = targetToBasicBlockMatchListMapit->second.erase(it);
				break;
			}
			else
			{
				addBasicBlockMatch = false;
			}
		}
	}

	if (addBasicBlockMatch)
	{
		BasicBlockMatch* p_basicBlockMatch = new BasicBlockMatch();
		memcpy(p_basicBlockMatch, &basicBlockMatch, sizeof(basicBlockMatch));
		targetToBasicBlockMatchListMapit->second.push_back(p_basicBlockMatch);
	}
}

void FunctionMatches::AddBasicBlockMatchList(va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<BasicBlockMatch> basicBlockMatchList)
{
	for (BasicBlockMatch basicBlockMatch : basicBlockMatchList)
	{
		AddBasicBlockMatch(sourceFunctionAddress, targetFunctionAddress, basicBlockMatch);
	}
}

void FunctionMatches::AddMatches(vector<BasicBlockMatch> currentBasicBlockMatchList)
{
	for (BasicBlockMatch basicBlockMatch : currentBasicBlockMatchList)
	{
		Function* p_src_function = m_sourceBinary->GetFunction(basicBlockMatch.Source);
		Function* p_target_function = m_targetBinary->GetFunction(basicBlockMatch.Target);

		if (p_src_function && p_target_function)
		{
			AddBasicBlockMatch(p_src_function->GetAddress(), p_target_function->GetAddress(), basicBlockMatch);
		}
	}
}

int FunctionMatches::DoInstructionHashMatch()
{
	for (auto& val : m_functionMatches)
	{
		va_t sourceFunctionAddress = val.first;
		vector<va_t> sourceFunctionAddresses = m_sourceBinary->GetFunction(sourceFunctionAddress)->GetBasicBlocks();
		for (auto& val2 : val.second)
		{
			va_t targetFunctionAddress = val2.first;

			vector<va_t> targetFunctionAddresses = m_targetBinary->GetFunction(targetFunctionAddress)->GetBasicBlocks();
			vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoBlocksInstructionHashMatch(sourceFunctionAddresses, targetFunctionAddresses);
			AddBasicBlockMatchList(sourceFunctionAddress, targetFunctionAddress, basicBlockMatchList);
		}
	}

	m_matchSequence++;

	return m_matchSequence - 1;
}

int FunctionMatches::DoControlFlowMatch(va_t address)
{
	if (address != 0)
	{
		unordered_map<va_t, unordered_map<va_t, vector<BasicBlockMatch*>>>::iterator it = m_functionMatches.find(address);
		if (it != m_functionMatches.end())
		{
			va_t sourceFunctionAddress = it->first;
			for (auto& val2 : it->second)
			{
				vector<BasicBlockMatch> fullBasicBlockMatchList;
				va_t targetFunctionAddress = val2.first;
				for (BasicBlockMatch *p_basicBlockMatch : val2.second)
				{
					vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoControlFlowMatch(p_basicBlockMatch->Source, p_basicBlockMatch->Target, CREF_FROM);
					fullBasicBlockMatchList.insert(fullBasicBlockMatchList.end(), basicBlockMatchList.begin(), basicBlockMatchList.end());
				}
				AddBasicBlockMatchList(sourceFunctionAddress, targetFunctionAddress, fullBasicBlockMatchList);
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
				vector<BasicBlockMatch> fullBasicBlockMatchList;
				va_t targetFunctionAddress = val2.first;

				for (BasicBlockMatch *p_basicBlockMatch : val2.second)
				{
					vector<BasicBlockMatch> basicBlockMatchList = m_pdiffAlgorithms->DoControlFlowMatch(p_basicBlockMatch->Source, p_basicBlockMatch->Target, CREF_FROM);
					fullBasicBlockMatchList.insert(fullBasicBlockMatchList.end(), basicBlockMatchList.begin(), basicBlockMatchList.end());
				}
				AddBasicBlockMatchList(sourceFunctionAddress, targetFunctionAddress, fullBasicBlockMatchList);
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
	vector<FunctionMatch> functionBasicBlockMatchList;

	for (auto& val : m_functionMatches)
	{
		va_t sourceFunctionAddress = val.first;
		for (auto& val2 : val.second)
		{
			FunctionMatch functionMatch;
			functionMatch.SourceFunction = sourceFunctionAddress;
			functionMatch.TargetFunction = val2.first;
			functionMatch.BasicBlockMatchList = val2.second;
			functionBasicBlockMatchList.push_back(functionMatch);
		}
	}

	return functionBasicBlockMatchList;
}
