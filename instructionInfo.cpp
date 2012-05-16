#include "instructionInfo.h"
#include <cstring>

InstructionInfo::InstructionInfo(unsigned char* a, int l) : addr(a), len(l)
{
}

bool InstructionInfo::operator==(InstructionInfo& a)
{
	if (len != a.len) return false;
	DISASM disasm1, disasm2;
	(void) memset (&(disasm1), 0, sizeof(DISASM));
	(void) memset (&(disasm2), 0, sizeof(DISASM));
	disasm1.EIP = (UIntPtr) addr;
	disasm2.EIP = (UIntPtr) a.addr;
	Disasm(&disasm1);
	Disasm(&disasm2);
	return	(disasm1.Instruction.Opcode == disasm2.Instruction.Opcode) &&
		(disasm1.Argument1.ArgType == disasm2.Argument1.ArgType) &&
		(disasm1.Argument2.ArgType == disasm2.Argument2.ArgType) &&
		(disasm1.Argument3.ArgType == disasm2.Argument3.ArgType) &&
		checkArgs(disasm1.Argument1, disasm2.Argument1) &&
		checkArgs(disasm1.Argument2, disasm2.Argument2) &&
		checkArgs(disasm1.Argument3, disasm2.Argument3);
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
