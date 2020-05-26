#include "Structures.h"
#include "DiffAlgorithms.h"

void DiffAlgorithms::DoInstructionHashMatch(BasicBlocks &srcBasicBlocks, BasicBlocks &targetBasicBlocks)
{
	//MATCHMAP* p_match_map = new MATCHMAP;

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
				match_data.Addresses[0] = val.second;
				match_data.Addresses[1] = patchedInstructionHashIt->second;
				match_data.MatchRate = 100;

				LogMessage(0, __FUNCTION__, "%X-%X: %d%%\n", match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);
				// p_match_map->insert(MatchMap_Pair(match_data.Addresses[0], match_data));
			}
		}
	}
}
