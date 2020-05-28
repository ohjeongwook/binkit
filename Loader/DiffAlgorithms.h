#pragma once

#include "BasicBlocks.h"

class DiffAlgorithms
{
private:
	BasicBlocks m_srcBasicBlocks;
	BasicBlocks m_targetBasicBlocks;
public:
	DiffAlgorithms();
	DiffAlgorithms(BasicBlocks& srcBasicBlocks, BasicBlocks& targetBasicBlocks);
    vector<MatchData> DoInstructionHashMatch();
	int GetInstructionHashMatchRate(vector<unsigned char> instructionHash1, vector<unsigned char> instructionHash2);
	vector<MatchData> DoControlFlowMatch(va_t sourceAddress, va_t targetAddressess, int type);
	vector<MatchData> DoControlFlowMatches(vector<MatchData> inputMatches);
};
