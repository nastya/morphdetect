#ifndef __INSTRUCTION_INFO_H
#define __INSTRUCTION_INFO_H

#include <beaengine/BeaEngine.h>

struct InstructionInfo
{
public:
	InstructionInfo(unsigned char* a, int l);
	bool operator==(InstructionInfo& a);

	unsigned char* addr;
	int len;
private:
	bool checkArgs(ARGTYPE arg1, ARGTYPE arg2);
};

#endif //__INSTRUCTION_INFO_H
