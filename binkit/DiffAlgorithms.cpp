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
	m_ptargetBasicBlocks = targetBinary.GetBasicBlocks();
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

vector<MatchData> DiffAlgorithms::DoBlocksInstructionHashMatch(vector<va_t>& sourceBlockAddresses, vector<va_t>& targetBlockAddresses)
{
	vector<MatchData> matcDataList;
	unordered_set<va_t> targetBlockAddressSet;

	for (va_t address : targetBlockAddresses)
	{
		targetBlockAddressSet.insert(address);
	}

	for (va_t sourceAddress : sourceBlockAddresses)
	{
		vector<unsigned char> instructionHash = m_psourceBasicBlocks->GetInstructionHash(sourceAddress);
		vector<va_t> targetAddresses;

		for (va_t targetAddress : m_ptargetBasicBlocks->GetInstructionHashMatches(instructionHash))
		{
			if (targetBlockAddressSet.find(targetAddress) == targetBlockAddressSet.end())
			{
				continue;
			}

			targetAddresses.push_back(targetAddress);
		}

		if (targetAddresses.size() == 1)
		{
			MatchData matchData;
			memset(&matchData, 0, sizeof(MatchData));
			matchData.Type = INSTRUCTION_HASH_INSIDE_FUNCTION_MATCH;
			matchData.Source = sourceAddress;
			matchData.Target = targetAddresses[0];
			matchData.MatchRate = 100;
			matcDataList.push_back(matchData);
		}
	}

	return matcDataList;
}

vector<MatchData> DiffAlgorithms::DoFunctionInstructionHashMatch(Function* sourceFunction, Function* targetFunction)
{
	vector<va_t> sourceBasicBlocks = sourceFunction->GetBasicBlocks();
	vector<va_t> targetBasicBlocks = targetFunction->GetBasicBlocks();

	return DoBlocksInstructionHashMatch(sourceBasicBlocks, targetBasicBlocks);
}

MatchDataCombinations* DiffAlgorithms::GenerateMatchDataCombinations(vector<MatchData> matchDataList)
{
	unordered_map<va_t, vector<MatchData>> matchMap;
	for (MatchData matchData : matchDataList)
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

vector<MatchDataCombination*> DiffAlgorithms::GetMatchDataCombinations(vector<MatchData> matchDataList)
{
	MatchDataCombinations* p_matchDataCombinations = GenerateMatchDataCombinations(matchDataList);
	return p_matchDataCombinations->GetTopMatches();
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
			matchData.SourceParent = sourceAddress;
			matchData.TargetParent = targetAddressess;
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
				matchData.SourceParent = sourceAddress;
				matchData.TargetParent = targetAddressess;
				matchData.Source = sourceAddresses[i];
				matchData.Target = targetAddresses[j];
				matchData.ReferenceOrderDifference = abs(i - j);
				matchData.MatchRate = GetInstructionHashMatchRate(srcInstructionHash, targetInstructionHash);
				controlFlowMatches.push_back(matchData);
			}
			else if (srcInstructionHash.size() == 0 && targetInstructionHash.size() == 0)
			{
				MatchData matchData;
				memset(&matchData, 0, sizeof(MatchData));
				matchData.Type = CONTROLFLOW_MATCH;
				matchData.SourceParent = sourceAddress;
				matchData.TargetParent = targetAddressess;
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

	return GetMatchDataCombinations(controlFlowMatches);
}

string DiffAlgorithms::GetMatchTypeStr(int Type)
{
	if (Type < sizeof(MatchDataTypeStr) / sizeof(MatchDataTypeStr[0]))
	{
		return MatchDataTypeStr[Type];
	}
	return "Unknown";
}
