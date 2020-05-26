#pragma once

#include "BasicBlocks.h"

class DiffAlgorithms
{
public:
    vector<MatchData> DoInstructionHashMatch(BasicBlocks& srcBasicBlocks, BasicBlocks& targetBasicBlocks);
};
