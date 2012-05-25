#include "instructionInfo.h"
#include "wrappers.h"
#include <cstring>

InstructionInfo::InstructionInfo(DISASM *disasm, int l) : len(l)
{
	memcpy(&(this->disasm), disasm, sizeof(DISASM));
}

bool InstructionInfo::operator==(InstructionInfo& a)
{
	if (len != a.len) return false;
	return	(disasm.Instruction.Opcode == a.disasm.Instruction.Opcode) &&
		(disasm.Argument1.ArgType == a.disasm.Argument1.ArgType) &&
		(disasm.Argument2.ArgType == a.disasm.Argument2.ArgType) &&
		(disasm.Argument3.ArgType == a.disasm.Argument3.ArgType) &&
		checkArgs(disasm.Argument1, a.disasm.Argument1) &&
		checkArgs(disasm.Argument2, a.disasm.Argument2) &&
		checkArgs(disasm.Argument3, a.disasm.Argument3);
}

bool InstructionInfo::checkArgs(ARGTYPE arg1, ARGTYPE arg2)
{
	if (arg1.ArgType & REGISTER_TYPE)
	{
		return arg1.ArgSize == arg2.ArgSize;
	}
	if (arg1.ArgType & MEMORY_TYPE)
	{
		return (arg1.Memory.Scale == arg2.Memory.Scale) && (arg1.Memory.Displacement == arg2.Memory.Displacement);
	}
	return strcmp(arg1.ArgMnemonic, arg2.ArgMnemonic) == 0;
}
