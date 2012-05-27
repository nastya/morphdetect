#ifndef __INSTRUCTION_QUEUE_H
#define __INSTRUCTION_QUEUE_H

#include <vector>
#include <unordered_map>
#include "instructionInfo.h"

using namespace std;

class InstructionQueue : public vector<InstructionInfo>
{
public:
	InstructionQueue();
	void fillStat();
	/*const */unordered_map<uint64_t, uint32_t> &stat();

private:
	unordered_map<uint64_t, uint32_t> _stat;
};

#endif //__INSTRUCTION_QUEUE_H
