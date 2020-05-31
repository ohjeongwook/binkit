#pragma once
#include <unordered_map>

#include "BasicBlocks.h"
#include "Log.h"

using namespace std;

class AddressPair
{
public:
	va_t SourceAddress;
	va_t TargetAddress;

	AddressPair(va_t sourceAddress = 0, va_t targetAddress = 0)
	{
		SourceAddress = sourceAddress;
		TargetAddress = targetAddress;
	}
};

class MatchDataCombination
{
private:
	vector<MatchData> m_matchDataList;
	float m_matchRateTotal = 0;

public:
	MatchDataCombination()
	{
		m_matchRateTotal = 0;
	}

	void Add(va_t source, MatchData& matchData)
	{
		MatchData newMatchData;
		memcpy(&newMatchData, &matchData, sizeof(MatchData));

		LogMessage(0, __FUNCTION__, "%x (%x) %x\n", source, newMatchData.Source, newMatchData.Target);
		m_matchDataList.push_back(newMatchData);
		m_matchRateTotal += newMatchData.MatchRate;
	}

	int Count()
	{
		return m_matchDataList.size();
	}

	MatchData Get(int index)
	{
		return m_matchDataList.at(index);
	}

	bool FindSource(va_t address)
	{
		LogMessage(0, __FUNCTION__, "%x\n", address);
		for (MatchData matchData : m_matchDataList)
		{
			if (matchData.Source == address)
			{
				LogMessage(0, __FUNCTION__, "return true\n");
				return true;
			}
		}

		LogMessage(0, __FUNCTION__, "return false\n");
		return false;
	}

	bool FindTarget(va_t address)
	{
		LogMessage(0, __FUNCTION__, "%x\n", address);
		for (MatchData matchData : m_matchDataList)
		{
			if (matchData.Target == address)
			{
				LogMessage(0, __FUNCTION__, "return true\n");
				return true;
			}
		}

		LogMessage(0, __FUNCTION__, "return false\n");
		return false;
	}

	void Print()
	{
		for (MatchData matchData : m_matchDataList)
		{
			printf("    %x - %x matchRate: %d \n", matchData.Source, matchData.Target, matchData.MatchRate);
		}
		printf("averageMatchRate : %f\n", GetMatchRate());
	}

	float GetMatchRate()
	{
		if (m_matchDataList.size() > 0)
		{
			return m_matchRateTotal / m_matchDataList.size();
		}

		return 0;
	}
};

class MatchDataCombinations
{
private:
	unordered_map<va_t, unordered_set<va_t>> m_processedAddresses;
	vector<MatchDataCombination *> m_combinations;

public:
	bool IsNew(va_t source, va_t target)
	{
		LogMessage(0, __FUNCTION__, "%x %x\n", source, target);
		unordered_map<va_t, unordered_set<va_t>>::iterator it = m_processedAddresses.find(source);
		if (it == m_processedAddresses.end())
		{
			unordered_set<va_t> addressMap;
			addressMap.insert(target);
			m_processedAddresses.insert({ source, addressMap });
		}
		else
		{
			if (it->second.find(target) != it->second.end())
			{
				return false;
			}
			it->second.insert(target);
		}

		return true;
	}

	MatchDataCombination* Add(va_t source, MatchData &matchData)
	{
		LogMessage(0, __FUNCTION__, "%x %x\n", source, matchData.Target);
		MatchDataCombination* p_addressPairCombination = new MatchDataCombination();
		p_addressPairCombination->Add(source, matchData);
		m_combinations.push_back(p_addressPairCombination);

		return p_addressPairCombination;
	}

	void Print()
	{
		for (MatchDataCombination* p_combination : m_combinations)
		{
			p_combination->Print();
		}
	}

	vector<MatchDataCombination*> GetTopSelection()
	{
		vector<MatchDataCombination*> matchDataCombinations;
		float maxMatchRate = 0;
		MatchDataCombination* p_selectedMatchDataCombination = NULL;
		for (MatchDataCombination* p_combination : m_combinations)
		{
			float matchRate = p_combination->GetMatchRate();

			if (maxMatchRate < matchRate)
			{
				maxMatchRate = matchRate;
			}
		}

		for (MatchDataCombination* p_matchDataCombination : m_combinations)
		{
			float matchRate = p_matchDataCombination->GetMatchRate();

			if (maxMatchRate == matchRate)
			{
				matchDataCombinations.push_back(p_matchDataCombination);
			}
		}
		return matchDataCombinations;
	}
};

class DiffAlgorithms
{
private:
	BasicBlocks m_srcBasicBlocks;
	BasicBlocks m_targetBasicBlocks;
	MatchDataCombinations* GenerateMatchDataCombinations(vector<MatchData> controlFlowMatches);

public:
	DiffAlgorithms();
	DiffAlgorithms(BasicBlocks& srcBasicBlocks, BasicBlocks& targetBasicBlocks);
    vector<MatchData> DoInstructionHashMatch();
	int GetInstructionHashMatchRate(vector<unsigned char> instructionHash1, vector<unsigned char> instructionHash2);
	vector<MatchData> DoControlFlowMatch(va_t sourceAddress, va_t targetAddressess, int type);	
	vector<MatchDataCombination*> DoControlFlowMatches(vector<AddressPair> addressPairs, int matchType);
};
