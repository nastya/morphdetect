#ifndef __INSTRUCTION_QUEUE_H
#define __INSTRUCTION_QUEUE_H

#include <vector>
#include <unordered_map>
#include "instructionInfo.h"

namespace detect_similar
{

using namespace std;

class InstructionQueue : public vector<InstructionInfo>
{
public:
	InstructionQueue();
	int bestMatch(InstructionQueue *models, int models_count, float threshold, float *coef_out = NULL, float *ans_out = NULL);

private:
	inline bool diffPossible(InstructionQueue &model, float threshold);
	inline void statCheck();
	inline void statFill();

	unordered_map<uint64_t, uint32_t> _stat;
};

} //namespace detect_similar

#endif //__INSTRUCTION_QUEUE_H
