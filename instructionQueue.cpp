#include "instructionQueue.h"

InstructionQueue::InstructionQueue()
 : vector<InstructionInfo>()
{
}

/*const */unordered_map<uint64_t, uint32_t> &InstructionQueue::stat()
{
	if (_stat.empty())
		fillStat();
	return _stat;
}

void InstructionQueue::fillStat()
{
	_stat.clear();
	for (auto &x : *this)
		_stat[x.hash]++;
}
