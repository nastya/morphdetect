#ifndef __INSTRUCTION_INFO_H
#define __INSTRUCTION_INFO_H

#include <beaengine/BeaEngine.h>

struct InstructionInfo
{
public:
	InstructionInfo(DISASM *disasm, int l);
	bool operator==(InstructionInfo& a);

	int len;
	DISASM disasm;
private:
	bool checkArgs(ARGTYPE arg1, ARGTYPE arg2);
};

#endif //__INSTRUCTION_INFO_H
