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

class BasicBlockMatchCombination
{
private:
	vector<BasicBlockMatch> m_basicBlockMatchList;
	float m_matchRateTotal = 0;

public:
	BasicBlockMatchCombination()
	{
		m_matchRateTotal = 0;
	}

	BasicBlockMatchCombination(BasicBlockMatchCombination* p_basicBlockMatchCombination)
	{
		for (BasicBlockMatch basicBlockMatch : p_basicBlockMatchCombination->GetBasicBlockMatchList())
		{
			m_basicBlockMatchList.push_back(basicBlockMatch);
			m_matchRateTotal += basicBlockMatch.MatchRate;
		}
	}

	void Add(va_t source, BasicBlockMatch& basicBlockMatch)
	{
		BasicBlockMatch newBasicBlockMatch;
		memcpy(&newBasicBlockMatch, &basicBlockMatch, sizeof(BasicBlockMatch));

		LogMessage(0, __FUNCTION__, "%x - %x\n", source, newBasicBlockMatch.Target);
		m_basicBlockMatchList.push_back(newBasicBlockMatch);
		m_matchRateTotal += newBasicBlockMatch.MatchRate;
	}

	size_t Count()
	{
		return m_basicBlockMatchList.size();
	}

	BasicBlockMatch Get(int index)
	{
		return m_basicBlockMatchList.at(index);
	}

	vector<BasicBlockMatch> GetBasicBlockMatchList()
	{
		return m_basicBlockMatchList;
	}

	vector<AddressPair> GetAddressPairs()
	{
		vector<AddressPair> addressPairs;
		for (auto& val : m_basicBlockMatchList)
		{
			addressPairs.push_back(AddressPair(val.Source, val.Target));
		}

		return addressPairs;
	}

	bool FindSource(va_t address)
	{
		LogMessage(0, __FUNCTION__, "%x\n", address);
		for (BasicBlockMatch basicBlockMatch : m_basicBlockMatchList)
		{
			if (basicBlockMatch.Source == address)
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
		for (BasicBlockMatch basicBlockMatch : m_basicBlockMatchList)
		{
			if (basicBlockMatch.Target == address)
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
		printf("* BasicBlockMatchCombination:\n");
		for (BasicBlockMatch basicBlockMatch : m_basicBlockMatchList)
		{
			printf("%x - %x matchRate: %d \n", basicBlockMatch.Source, basicBlockMatch.Target, basicBlockMatch.MatchRate);
		}
		printf("averageMatchRate : %f\n", GetMatchRate());
	}

	float GetMatchRate()
	{
		if (m_basicBlockMatchList.size() > 0)
		{
			return m_matchRateTotal / m_basicBlockMatchList.size();
		}

		return 0;
	}
};

class BasicBlockMatchCombinations
{
private:
	unordered_map<va_t, unordered_set<va_t>> m_processedAddresses;
	vector<BasicBlockMatchCombination *>* m_pcombinations;

public:
	BasicBlockMatchCombinations()
	{
		m_pcombinations = new vector<BasicBlockMatchCombination*>;
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

	BasicBlockMatchCombination* Add(va_t source, BasicBlockMatch &basicBlockMatch)
	{
		LogMessage(0, __FUNCTION__, "%x %x\n", source, basicBlockMatch.Target);
		BasicBlockMatchCombination* p_addressPairCombination = new BasicBlockMatchCombination();
		p_addressPairCombination->Add(source, basicBlockMatch);
		m_pcombinations->push_back(p_addressPairCombination);

		return p_addressPairCombination;
	}

	void AddCombinations(va_t source, vector<BasicBlockMatch> &basicBlockMatchList)
	{
		LogMessage(0, __FUNCTION__, "basicBlockMatchList.size(): %d\n", basicBlockMatchList.size());

		if (m_pcombinations->size() == 0)
		{
			for (BasicBlockMatch basicBlockMatch : basicBlockMatchList)
			{
				LogMessage(0, __FUNCTION__, "+ %x - %x\n", source, basicBlockMatch.Target);
				Add(source, basicBlockMatch);
			}
		}
		else
		{
			vector<BasicBlockMatchCombination*>* p_newCombinations = new vector<BasicBlockMatchCombination*>;
			for (BasicBlockMatchCombination* p_basicBlockMatchCombination : *m_pcombinations)
			{
				for (BasicBlockMatch basicBlockMatch : basicBlockMatchList)
				{
					LogMessage(0, __FUNCTION__, "+ %x - %x\n", source, basicBlockMatch.Target);
					BasicBlockMatchCombination* p_duplicatedBasicBlockMatchCombination = new BasicBlockMatchCombination(p_basicBlockMatchCombination);
					p_duplicatedBasicBlockMatchCombination->Add(source, basicBlockMatch);
					p_newCombinations->push_back(p_duplicatedBasicBlockMatchCombination);
				}
			}
			delete m_pcombinations;
			m_pcombinations = p_newCombinations;		
		}

		LogMessage(0, __FUNCTION__, "size(): %d\n", m_pcombinations->size());
	}

	void Print()
	{
		for (BasicBlockMatchCombination* p_combination : *m_pcombinations)
		{
			p_combination->Print();
		}
	}

	vector<BasicBlockMatchCombination*> GetTopMatches()
	{
		vector<BasicBlockMatchCombination*> basicBlockMatchCombinations;
		float maxMatchRate = 0;
		BasicBlockMatchCombination* p_selectedBasicBlockMatchCombination = NULL;
		for (BasicBlockMatchCombination* p_combination : *m_pcombinations)
		{
			float matchRate = p_combination->GetMatchRate();

			if (maxMatchRate < matchRate)
			{
				maxMatchRate = matchRate;
			}
		}

		for (BasicBlockMatchCombination* p_basicBlockMatchCombination : *m_pcombinations)
		{
			float matchRate = p_basicBlockMatchCombination->GetMatchRate();

			if (maxMatchRate == matchRate)
			{
				basicBlockMatchCombinations.push_back(p_basicBlockMatchCombination);
			}
		}
		return basicBlockMatchCombinations;
	}

	vector<BasicBlockMatchCombination*>* GetCombinations()
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
	BasicBlockMatchCombinations* GenerateBasicBlockMatchCombinations(vector<BasicBlockMatch> basicBlockMatchList);

public:
	DiffAlgorithms();
	DiffAlgorithms(Binary* p_sourceBinary, Binary* p_targetBinary);
	int GetInstructionHashMatchRate(vector<unsigned char> instructionHash1, vector<unsigned char> instructionHash2);
	vector<BasicBlockMatch> DoInstructionHashMatch();
	vector<BasicBlockMatch> DoBlocksInstructionHashMatch(vector<va_t>& sourceBlockAddresses, vector<va_t>& targetBlockAddresses);
	vector<BasicBlockMatch> DoFunctionInstructionHashMatch(Function* sourceFunction, Function* targetFunction);

	vector<BasicBlockMatchCombination*> GetBasicBlockMatchCombinations(vector<BasicBlockMatch> basicBlockMatchList);
	vector<BasicBlockMatch> DoControlFlowMatch(va_t sourceAddress, va_t targetAddress, int type);
	vector<BasicBlockMatchCombination*> DoControlFlowMatches(vector<AddressPair> addressPairs, int matchType);
	string GetMatchTypeStr(int Type);
};
