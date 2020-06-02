#include "Structures.h"
#include "Utility.h"
#include "DiffAlgorithms.h"
#include "Diff.h"
#include<algorithm>

DiffAlgorithms::DiffAlgorithms()
{
	m_debugLevel = 0;
}

DiffAlgorithms::DiffAlgorithms(Binary& sourceBinary, Binary& targetBinary)
{
	m_debugLevel = 0;
	m_psourceBasicBlocks = sourceBinary.GetBasicBlocks();
	m_psourceFunctions = sourceBinary.GetFunctions();
	m_ptargetBasicBlocks = targetBinary.GetBasicBlocks();
	m_ptargetFunctions = targetBinary.GetFunctions();
}

DiffAlgorithms::DiffAlgorithms(BasicBlocks *p_sourceBasicBlocks, BasicBlocks* p_targetBasicBlocks)
{
	m_debugLevel = 0;
	m_psourceBasicBlocks = p_sourceBasicBlocks;
	m_ptargetBasicBlocks = p_targetBasicBlocks;
}

DiffAlgorithms::DiffAlgorithms(BasicBlocks *p_sourceBasicBlocks, Functions *p_sourceFunctions, BasicBlocks* p_targetBasicBlocks, Functions *p_targetFunctions)
{
	m_debugLevel = 0;
	m_psourceBasicBlocks = p_sourceBasicBlocks;
	m_psourceFunctions = p_sourceFunctions;
	m_ptargetBasicBlocks = p_targetBasicBlocks;
	m_ptargetFunctions = p_targetFunctions;
}


vector<MatchData> DiffAlgorithms::DoInstructionHashMatch()
{
	vector<MatchData> matchDataList;

	InstructionHashMap *p_srcInstructionHashMap = m_psourceBasicBlocks->GetInstructionHashes();
	InstructionHashMap* p_targetInstructionHashMap = m_ptargetBasicBlocks->GetInstructionHashes();

	for (auto& val : *p_srcInstructionHashMap)
	{
		// Only when the hash is unique
		if (p_srcInstructionHashMap->count(val.first) == 1 && p_targetInstructionHashMap->count(val.first) == 1)
		{
			multimap <vector<unsigned char>, va_t>::iterator patchedInstructionHashIt = p_targetInstructionHashMap->find(val.first);
			if (patchedInstructionHashIt != p_targetInstructionHashMap->end())
			{
				MatchData matchData;
				memset(&matchData, 0, sizeof(MatchData));
				matchData.Type = INSTRUCTION_HASH_MATCH;
				matchData.Source = val.second;
				matchData.Target = patchedInstructionHashIt->second;
				matchData.MatchRate = 100;
				matchDataList.push_back(matchData);
			}
		}
	}

	return matchDataList;
}

int DiffAlgorithms::GetInstructionHashMatchRate(vector<unsigned char> instructionHash1, vector<unsigned char> instructionHash2)
{
	int matchRate = 0;

	int lengthDifference = (instructionHash1.size() - instructionHash2.size());
	if (lengthDifference > instructionHash1.size() * 0.5 || lengthDifference > instructionHash2.size() * 0.5)
	{
		matchRate = 0;
	}
	else
	{
		matchRate = GetStringSimilarity(BytesToHexString(instructionHash1).c_str(), BytesToHexString(instructionHash2).c_str());
	}
	return matchRate;
}

MatchDataCombinations* DiffAlgorithms::GenerateMatchDataCombinations(vector<MatchData> controlFlowMatches)
{
	unordered_map<va_t, vector<MatchData>> matchMap;
	for (MatchData matchData : controlFlowMatches)
	{
		LogMessage(0, __FUNCTION__, "%x-%x: %d%%\n", matchData.Source, matchData.Target, matchData.MatchRate);
		unordered_map<va_t, vector<MatchData>>::iterator it = matchMap.find(matchData.Source);
		if (it == matchMap.end())
		{
			vector<MatchData> matchDatalist;
			matchDatalist.push_back(matchData);
			matchMap.insert(pair<va_t, vector<MatchData>>(matchData.Source, matchDatalist));
		}
		else
		{
			bool isNew = true;
			for (MatchData matchData2 : it->second)
			{
				if (matchData.Source == matchData2.Source && matchData.Target == matchData2.Target)
				{
					isNew = false;
					break;
				}
			}

			if (isNew)
			{
				it->second.push_back(matchData);
			}
		}
	}

	MatchDataCombinations* p_matchDataCombinations = new MatchDataCombinations();

	if (matchMap.empty())
	{
		return p_matchDataCombinations;
	}

	for (auto& val : matchMap)
	{
		p_matchDataCombinations->AddCombinations(val.first, val.second);
	}
	return p_matchDataCombinations;
}

vector<MatchData> DiffAlgorithms::DoControlFlowMatch(va_t sourceAddress, va_t targetAddressess, int type)
{
	bool debug = false;
	vector<MatchData> controlFlowMatches;

	vector<va_t> sourceAddresses = m_psourceBasicBlocks->GetCodeReferences(sourceAddress, type);
	vector<va_t> targetAddresses = m_ptargetBasicBlocks->GetCodeReferences(targetAddressess, type);

	if (sourceAddresses.size() == 0 || targetAddresses.size() == 0)
	{
		return controlFlowMatches;
	}

	if (sourceAddresses.size() > 2 && sourceAddresses.size() == targetAddresses.size() && type == CREF_FROM)
	{
		//Special case for switch case
		for (int i = 0; i < sourceAddresses.size(); i++)
		{
			MatchData matchData;
			memset(&matchData, 0, sizeof(MatchData));
			matchData.Type = CONTROLFLOW_MATCH;
			matchData.Source = sourceAddresses[i];
			matchData.Target = targetAddresses[i];
			matchData.MatchRate = GetInstructionHashMatchRate(m_psourceBasicBlocks->GetInstructionHash(sourceAddresses[i]), m_ptargetBasicBlocks->GetInstructionHash(targetAddresses[i]));
			controlFlowMatches.push_back(matchData);
		}
		return controlFlowMatches;
	}

	multimap <va_t, va_t> matchDataMap;
	for (int i = 0; i < sourceAddresses.size(); i++)
	{
		vector<unsigned char> srcInstructionHash = m_psourceBasicBlocks->GetInstructionHash(sourceAddresses[i]);

		for (int j = 0; j < targetAddresses.size(); j++)
		{
			bool skip = false;

			for (multimap <va_t, va_t>::iterator it = matchDataMap.find(sourceAddresses[i]); it != matchDataMap.end() && it->first == sourceAddresses[i]; it++)
			{
				if (it->second == targetAddresses[j])
				{
					skip = true;
					break;
				}
			}

			if (skip)
				continue;

			matchDataMap.insert(pair<va_t, va_t>(sourceAddresses[i], targetAddresses[j]));
			vector<unsigned char> targetInstructionHash = m_ptargetBasicBlocks->GetInstructionHash(targetAddresses[j]);

			if (srcInstructionHash.size() > 0 && targetInstructionHash.size() > 0)
			{
				MatchData matchData;
				memset(&matchData, 0, sizeof(MatchData));
				matchData.Type = CONTROLFLOW_MATCH;
				matchData.Source = sourceAddresses[i];
				matchData.Target = targetAddresses[j];
				matchData.ReferenceOrderDifference = abs(i - j);
				matchData.MatchRate = GetInstructionHashMatchRate(srcInstructionHash, targetInstructionHash);
				controlFlowMatches.push_back(matchData);
			}
			else if (srcInstructionHash.size() ==0 && targetInstructionHash.size() == 0)
			{
				MatchData matchData;
				memset(&matchData, 0, sizeof(MatchData));
				matchData.Type = CONTROLFLOW_MATCH;
				matchData.Source = sourceAddresses[i];
				matchData.Target = targetAddresses[j];
				matchData.ReferenceOrderDifference = abs(i - j);
				matchData.MatchRate = 100;
				controlFlowMatches.push_back(matchData);
			}
		}
	}

	return controlFlowMatches;
}

vector<MatchDataCombination*> DiffAlgorithms::DoControlFlowMatches(vector<AddressPair> addressPairs, int matchType)
{
	int processed_count = 0;
	vector<MatchData> controlFlowMatches;

	for (AddressPair addressPair : addressPairs)
	{
		vector<MatchData> newControlFlowMatches = DiffAlgorithms::DoControlFlowMatch(addressPair.SourceAddress, addressPair.TargetAddress, matchType);
		controlFlowMatches.insert(controlFlowMatches.end(), newControlFlowMatches.begin(), newControlFlowMatches.end());
	}

	MatchDataCombinations* p_matchDataCombinations = GenerateMatchDataCombinations(controlFlowMatches);
	return p_matchDataCombinations->GetTopMatches();
}

vector<MatchData> DiffAlgorithms::DoInstructionHashMatchInBlocks(vector<va_t>& sourceBlockAddresses, vector<va_t>& targetBlockAddresses)
{
	vector<MatchData> matcDataList;
	unordered_set<va_t> targetBlockAddressesMap;

	for (va_t address : targetBlockAddresses)
	{
		targetBlockAddressesMap.insert(address);
	}

	for (va_t sourceAddress : sourceBlockAddresses)
	{
		vector<unsigned char> instructionHash = m_psourceBasicBlocks->GetInstructionHash(sourceAddress);
		for (va_t targetAddress : m_ptargetBasicBlocks->GetAddressesForInstructionHash(instructionHash))
		{
			if (targetBlockAddressesMap.find(targetAddress) == targetBlockAddressesMap.end())
			{
				continue;
			}

			MatchData matchData;
			memset(&matchData, 0, sizeof(MatchData));
			matchData.Type = INSTRUCTION_HASH_INSIDE_FUNCTION_MATCH;
			matchData.Source = sourceAddress;
			matchData.Target = targetAddress;
			matchData.MatchRate = 100;
			matcDataList.push_back(matchData);
		}
	}

	return matcDataList;
}

void DiffAlgorithms::AddFunctionMatchData(unordered_map<va_t, TargetToMatchDataListMap>& functionMatchMap, va_t sourceFunctionAddress, va_t targetFunctionAddress, MatchData matchData)
{
	unordered_map<va_t, TargetToMatchDataListMap>::iterator it = functionMatchMap.find(sourceFunctionAddress);
	if (it == functionMatchMap.end())
	{
		TargetToMatchDataListMap targetToMatchDataList;
		vector<MatchData> matchDataList;
		matchDataList.push_back(matchData);
		targetToMatchDataList.insert(pair<va_t, vector<MatchData>>(targetFunctionAddress, matchDataList));
		functionMatchMap.insert(pair<va_t, TargetToMatchDataListMap>(sourceFunctionAddress, targetToMatchDataList));
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
			targetToMatchDataListMapit->second.push_back(matchData);
		}
	}
}

void DiffAlgorithms::AddFunctionMatchDataList(unordered_map<va_t, TargetToMatchDataListMap>& functionMatchMap, va_t sourceFunctionAddress, va_t targetFunctionAddress, vector<MatchData> matchDataList)
{
	for (MatchData matchData : matchDataList)
	{
		AddFunctionMatchData(functionMatchMap, sourceFunctionAddress, targetFunctionAddress, matchData);
	}
}

void DiffAlgorithms::PrintFunctionMatchData(unordered_map<va_t, TargetToMatchDataListMap>& functionMatchMap)
{
	for (auto& val : functionMatchMap)
	{
		va_t sourceFunctionAddress = val.first;
		vector<va_t> sourceFunctionAddresses = m_psourceFunctions->GetBasicBlocks(sourceFunctionAddress);
		for (auto& val2 : val.second)
		{
			va_t targetFunctionAddress = val2.first;
			vector<va_t> targetFunctionAddresses = m_ptargetFunctions->GetBasicBlocks(targetFunctionAddress);

			printf("==========================================\n");
			printf("Function: %x - %x\n", sourceFunctionAddress, targetFunctionAddress);
			for (MatchData matchData : val2.second)
			{
				printf("\tMatch: %x-%x %d\n", matchData.Source, matchData.Target, matchData.MatchRate);
			}
		}
	}
}

vector<FunctionMatch> DiffAlgorithms::DoFunctionMatch(vector<MatchData> currentMatchDataList)
{
	vector<FunctionMatch> functionMatchDataList;
	unordered_map<va_t, TargetToMatchDataListMap> functionMatchMap;

	if (!m_psourceFunctions)
	{
		return functionMatchDataList;
	}

	if (!m_ptargetFunctions)
	{
		return functionMatchDataList;
	}

	// va_t sourceFunctionAddress,
	// From currentMatchDataList find matches for sourceFunctionAddress -> targetFunctionAddress
	// get sourceFunctionAddress basic blocks
	// get targetFunctionAddress basic blocks
	// Perform instruction hashes between them -> Call DoInstructionHashMatchInBlocks

	for (MatchData matchData : currentMatchDataList)
	{
		va_t sourceFunctionAddress;
		m_psourceFunctions->GetFunctionAddress(matchData.Source, sourceFunctionAddress);
		va_t targetFunctionAddress;
		m_ptargetFunctions->GetFunctionAddress(matchData.Target, targetFunctionAddress);

		AddFunctionMatchData(functionMatchMap, sourceFunctionAddress, targetFunctionAddress, matchData);
	}

	if (m_debugLevel > 0)
	{
		PrintFunctionMatchData(functionMatchMap);
	}

	for (auto& val : functionMatchMap)
	{
		va_t sourceFunctionAddress = val.first;
		vector<va_t> sourceFunctionAddresses = m_psourceFunctions->GetBasicBlocks(sourceFunctionAddress);
		for (auto& val2 : val.second)
		{
			va_t targetFunctionAddress = val2.first;

			vector<va_t> targetFunctionAddresses = m_ptargetFunctions->GetBasicBlocks(targetFunctionAddress);
			vector<MatchData> functionInstructionHashMatches = DoInstructionHashMatchInBlocks(sourceFunctionAddresses, targetFunctionAddresses);
			AddFunctionMatchDataList(functionMatchMap, sourceFunctionAddress, targetFunctionAddress, functionInstructionHashMatches);

			for (MatchData matchData : val2.second)
			{
				vector<MatchData> newFunctionControlFlowMatches = DoControlFlowMatch(matchData.Source, matchData.Target, CREF_FROM);
				AddFunctionMatchDataList(functionMatchMap, sourceFunctionAddress, targetFunctionAddress, newFunctionControlFlowMatches);
			}

			for (MatchData matchData : functionInstructionHashMatches)
			{
				vector<MatchData> newFunctionControlFlowMatches = DoControlFlowMatch(matchData.Source, matchData.Target, CREF_FROM);
				AddFunctionMatchDataList(functionMatchMap, sourceFunctionAddress, targetFunctionAddress, newFunctionControlFlowMatches);
			}
		}
	}

	if (m_debugLevel > 0)
	{
		printf("* Revised Function Maps:\n");
		PrintFunctionMatchData(functionMatchMap);
	}

	for (auto& val : functionMatchMap)
	{
		va_t sourceFunctionAddress = val.first;
		vector<va_t> sourceFunctionAddresses = m_psourceFunctions->GetBasicBlocks(sourceFunctionAddress);
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
