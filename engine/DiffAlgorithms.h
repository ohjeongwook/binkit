#pragma once
#include <unordered_map>

#include "Binary.h"
#include "BasicBlocks.h"
#include "Log.h"
#include "FunctionMatches.h"

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

	MatchDataCombination(MatchDataCombination* p_matchDataCombination)
	{
		for (MatchData matchData : p_matchDataCombination->GetMatchDataList())
		{
			m_matchDataList.push_back(matchData);
			m_matchRateTotal += matchData.MatchRate;
		}
	}

	void Add(va_t source, MatchData& matchData)
	{
		MatchData newMatchData;
		memcpy(&newMatchData, &matchData, sizeof(MatchData));

		LogMessage(0, __FUNCTION__, "%x - %x\n", source, newMatchData.Target);
		m_matchDataList.push_back(newMatchData);
		m_matchRateTotal += newMatchData.MatchRate;
	}

	size_t Count()
	{
		return m_matchDataList.size();
	}

	MatchData Get(int index)
	{
		return m_matchDataList.at(index);
	}

	vector<MatchData> GetMatchDataList()
	{
		return m_matchDataList;
	}

	vector<AddressPair> GetAddressPairs()
	{
		vector<AddressPair> addressPairs;
		for (auto& val : m_matchDataList)
		{
			addressPairs.push_back(AddressPair(val.Source, val.Target));
		}

		return addressPairs;
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
		printf("* MatchDataCombination:\n");
		for (MatchData matchData : m_matchDataList)
		{
			printf("%x - %x matchRate: %d \n", matchData.Source, matchData.Target, matchData.MatchRate);
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
	vector<MatchDataCombination *>* m_pcombinations;

public:
	MatchDataCombinations()
	{
		m_pcombinations = new vector<MatchDataCombination*>;
	}

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
		m_pcombinations->push_back(p_addressPairCombination);

		return p_addressPairCombination;
	}

	void AddCombinations(va_t source, vector<MatchData> &matchDataList)
	{
		LogMessage(0, __FUNCTION__, "matchDataList.size(): %d\n", matchDataList.size());

		if (m_pcombinations->size() == 0)
		{
			for (MatchData matchData : matchDataList)
			{
				LogMessage(0, __FUNCTION__, "+ %x - %x\n", source, matchData.Target);
				Add(source, matchData);
			}
		}
		else
		{
			vector<MatchDataCombination*>* p_newCombinations = new vector<MatchDataCombination*>;
			for (MatchDataCombination* p_matchDataCombination : *m_pcombinations)
			{
				for (MatchData matchData : matchDataList)
				{
					LogMessage(0, __FUNCTION__, "+ %x - %x\n", source, matchData.Target);
					MatchDataCombination* p_duplicatedMatchDataCombination = new MatchDataCombination(p_matchDataCombination);
					p_duplicatedMatchDataCombination->Add(source, matchData);
					p_newCombinations->push_back(p_duplicatedMatchDataCombination);
				}
			}
			delete m_pcombinations;
			m_pcombinations = p_newCombinations;		
		}

		LogMessage(0, __FUNCTION__, "size(): %d\n", m_pcombinations->size());
	}

	void Print()
	{
		for (MatchDataCombination* p_combination : *m_pcombinations)
		{
			p_combination->Print();
		}
	}

	vector<MatchDataCombination*> GetTopMatches()
	{
		vector<MatchDataCombination*> matchDataCombinations;
		float maxMatchRate = 0;
		MatchDataCombination* p_selectedMatchDataCombination = NULL;
		for (MatchDataCombination* p_combination : *m_pcombinations)
		{
			float matchRate = p_combination->GetMatchRate();

			if (maxMatchRate < matchRate)
			{
				maxMatchRate = matchRate;
			}
		}

		for (MatchDataCombination* p_matchDataCombination : *m_pcombinations)
		{
			float matchRate = p_matchDataCombination->GetMatchRate();

			if (maxMatchRate == matchRate)
			{
				matchDataCombinations.push_back(p_matchDataCombination);
			}
		}
		return matchDataCombinations;
	}

	vector<MatchDataCombination*>* GetCombinations()
	{
		return m_pcombinations;
	}
};

class DiffAlgorithms
{
private:
	int m_debugLevel;
	BasicBlocks *m_psourceBasicBlocks;
	BasicBlocks* m_ptargetBasicBlocks;
	MatchDataCombinations* GenerateMatchDataCombinations(vector<MatchData> matchDataList);

public:
	DiffAlgorithms();
	DiffAlgorithms(Binary& sourceBinary, Binary& targetBinary);
	int GetInstructionHashMatchRate(vector<unsigned char> instructionHash1, vector<unsigned char> instructionHash2);
	vector<MatchData> DoInstructionHashMatch();
	vector<MatchData> DoBlocksInstructionHashMatch(vector<va_t>& sourceBlockAddresses, vector<va_t>& targetBlockAddresses);
	vector<MatchData> DoFunctionInstructionHashMatch(Function* sourceFunction, Function* targetFunction);

	vector<MatchDataCombination*> GetMatchDataCombinations(vector<MatchData> matchDataList);
	vector<MatchData> DoControlFlowMatch(va_t sourceAddress, va_t targetAddress, int type);
	vector<MatchDataCombination*> DoControlFlowMatches(vector<AddressPair> addressPairs, int matchType);
	string GetMatchTypeStr(int Type);
};
