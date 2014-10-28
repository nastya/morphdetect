#ifndef __INSTRUCTION_INFO_H
#define __INSTRUCTION_INFO_H

#include <beaengine/BeaEngine.h>

namespace detect_similar
{

struct InstructionInfo
{
public:
	InstructionInfo(DISASM *disasm, int l);
	bool operator==(InstructionInfo& a);

	int len;
	DISASM disasm;
	uint64_t hash;
private:
	inline bool checkArgs(const ARGTYPE &arg1, const ARGTYPE &arg2) const;
	void build_hash();
	uint64_t arg_hash(const ARGTYPE &arg) const;
};

} //namespace detect_similar

#endif //__INSTRUCTION_INFO_H
