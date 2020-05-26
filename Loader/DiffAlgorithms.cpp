#include "Structures.h"
#include "DiffAlgorithms.h"

vector<MatchData> DiffAlgorithms::DoInstructionHashMatch(BasicBlocks &srcBasicBlocks, BasicBlocks &targetBasicBlocks)
{
	vector<MatchData> matchDataList;

	InstructionHashMap *p_srcInstructionHashMap = srcBasicBlocks.GetInstructionHashes();
	InstructionHashMap* p_targetInstructionHashMap = targetBasicBlocks.GetInstructionHashes();

	printf("DoInstructionHashMatch: %d vs %d\n", p_srcInstructionHashMap->size(), p_targetInstructionHashMap->size());
	for (auto& val : *p_srcInstructionHashMap)
	{
		// Only when the hash is unique
		if (p_srcInstructionHashMap->count(val.first) == 1 && p_targetInstructionHashMap->count(val.first) == 1)
		{
			multimap <vector<unsigned char>, va_t>::iterator patchedInstructionHashIt = p_targetInstructionHashMap->find(val.first);
			if (patchedInstructionHashIt != p_targetInstructionHashMap->end())
			{
				MatchData match_data;
				memset(&match_data, 0, sizeof(MatchData));
				match_data.Type = INSTRUCTION_HASH_MATCH;
				match_data.OriginalAddress = val.second;
				match_data.PatchedAddress = patchedInstructionHashIt->second;
				match_data.MatchRate = 100;

				LogMessage(0, __FUNCTION__, "%X-%X: %d%%\n", match_data.OriginalAddress, match_data.PatchedAddress, match_data.MatchRate);
				matchDataList.push_back(match_data);
			}
		}
	}

	return matchDataList;
}
