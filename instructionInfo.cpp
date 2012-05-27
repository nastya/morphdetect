#include "instructionInfo.h"
#include "wrappers.h"
#include <cstring>

#define INSTRUCTION_FUZZY

InstructionInfo::InstructionInfo(DISASM *disasm, int l) : len(l)
{
	memcpy(&(this->disasm), disasm, sizeof(DISASM));
	build_hash();
}

bool InstructionInfo::operator==(InstructionInfo& a)
{
	/*
	if ((hash != a.hash) && (strcmp(disasm.CompleteInstr, a.disasm.CompleteInstr) == 0)) {
		cerr << "HASH ERROR" << endl;
		cerr << "Checking instr: " << disasm.CompleteInstr << "; " << a.disasm.CompleteInstr << endl;
		cerr << "Hashes: " << hex << hash << "; " << a.hash << dec << endl;
	}
	*/
	/*
	if ((hash == a.hash) && (strcmp(disasm.CompleteInstr, a.disasm.CompleteInstr) != 0)) {
		cerr << "HASH COLLISION" << endl;
		cerr << "Checking instr: " << disasm.CompleteInstr << "; " << a.disasm.CompleteInstr << endl;
		cerr << "Hashes: " << hex << hash << "; " << a.hash << dec << endl;
	}
	*/

	return	(hash == a.hash) &&
		(disasm.Instruction.Immediat == a.disasm.Instruction.Immediat) &&
#ifndef INSTRUCTION_FUZZY
		(disasm.Argument1.ArgType == a.disasm.Argument1.ArgType) &&
		(disasm.Argument2.ArgType == a.disasm.Argument2.ArgType) &&
		(disasm.Argument3.ArgType == a.disasm.Argument3.ArgType) &&
#endif
		checkArgs(disasm.Argument1, a.disasm.Argument1) &&
		checkArgs(disasm.Argument2, a.disasm.Argument2) &&
		checkArgs(disasm.Argument3, a.disasm.Argument3);
}

bool InstructionInfo::checkArgs(const ARGTYPE &arg1, const ARGTYPE &arg2) const
{
	// We do not need anything more than ArgSize or Immediat here, and those were already checked.
	if (arg1.ArgType & (NO_ARGUMENT | REGISTER_TYPE | CONSTANT_TYPE))
		return true;

	// Memory.Scale was already checked inside hash, check Displacement only.
	if (arg1.ArgType & MEMORY_TYPE)
		return arg1.Memory.Displacement == arg2.Memory.Displacement;

	// cerr << "ERROR" << endl;
	// We should never get here. Just in case, check the strings.
	return strcmp(arg1.ArgMnemonic, arg2.ArgMnemonic) == 0;
}

/*
 * Length and opcode are not checked, mnemonics are compared instead.
 * Restricting length and opcode results in threating equivalent instructions like non-equivalent ones.
 */
/**
* full:		0xFFFFFFFFFFFFFFFF (64 bit)
* mnemonic hash:	0xFFFFFFFF00000000 (32 bit, padding: 32 bit)
* argument 1:	0x00000000FF000000 (8 bit, padding: 24 bit).
* argument 2:	0x0000000000FF0000 (8 bit, padding: 16 bit).
* argument 3:	0x000000000000FF00 (8 bit, padding: 8 bit).
* imm xor hash:	0x00000000000000FF (8 bit, padding: 0 bit)
*
* Excluded (old):
* //length:	0xF000000000000000 (4 bit, padding: 60 bit)
* //opcode:	0x00FFFFFF00000000 (24 bit, padding: 32 bit).
*/
void InstructionInfo::build_hash()
{
	// Instruction.Mnemonic hash. This can be (probably) trusted to be unique for each unique Instruction.Mnemonic.
	uint64_t mnemonic_hash = 0, imm_hash = 0;
	char *mnemonic = disasm.Instruction.Mnemonic;
	for (int i = 0; i < (int) strlen(mnemonic) - 1; i++) { // The last symbol is space, we don't need it
		uint64_t c = mnemonic[i] - 'a' + 1; // 1-26
		if ((c < 1) || (c > 26)) c = 27; // 1-27, 5 bit per letter
		/*
		* First 5 letters are stored completely unique (bits 1-25)
		* 6-th letter can be corrupted by the last letters (bits 26-30)
		* >=7-th letters are xored in the last 5 bits (bits 28-32), and can corrupt the 6-th letter
		*/
		if (i < 6) {
			mnemonic_hash |= c << (32 - (i + 1) * 5); // head: first 30 bits
		} else {
			mnemonic_hash |= c; // tail: last 5 bits, corrupts 3 bits from the head (6th letter)
		}
	}

	// Instruction.Immediat is stored only partially, should be checked after!
	if (disasm.Instruction.Immediat != 0) {
		for (int i = 0; i < 64; i += 8) {
			imm_hash ^= (disasm.Instruction.Immediat >> i) & 0xFF;
		}
	}

	hash = 0;
	//hash |= ((uint64_t) len) << 60; // 4 bit, padding: 60 bit
	//hash |= ((uint64_t) disasm.Instruction.Opcode) << 32; // 24 bit, padding: 32 bit
	hash |= mnemonic_hash << 32; // 32 bit, padding: 32 bit
	hash |= ((uint64_t) arg_hash(disasm.Argument1)) << 24; // 8 bit, padding: 24 bit
	hash |= ((uint64_t) arg_hash(disasm.Argument2)) << 16; // 8 bit, padding: 16 bit
	hash |= ((uint64_t) arg_hash(disasm.Argument3)) << 8; // 8 bit, padding: 8 bit
	hash |= imm_hash; // 8 bit, padding: 0 bit
}

/**
 * full:		11111111 (8 bit)
 * size:		11000000 (2 bit, padding: 6 bit)
 * type:		00110000 (2 bit, padding: 4 bit)
 * subtype:	00001111 (4 bit, padding: 0 bit)
 */
uint64_t InstructionInfo::arg_hash(const ARGTYPE &arg) const {
	Int32 type = arg.ArgType;
	if (type & NO_ARGUMENT)
		return 0;

	uint64_t size_bit = 0, type_bit = 0, subtype_bit = 0;

	switch (arg.ArgSize) {
	case 8:
		size_bit = 1;
		break;
	case 16:
		size_bit = 2;
		break;
	case 32:
		size_bit = 3;
		break;
	}

	if (type & REGISTER_TYPE) {
		type_bit = 1;
		if (type & MMX_REG) {
			subtype_bit = 1;
		} else if (type & GENERAL_REG) {
			subtype_bit = 2;
		} else if (type & FPU_REG) {
			subtype_bit = 3;
		} else if (type & SSE_REG) {
			subtype_bit = 4;
		} else if (type & CR_REG) {
			subtype_bit = 5;
		} else if (type & DR_REG) {
			subtype_bit = 6;
		} else if (type & SPECIAL_REG) {
			subtype_bit = 7;
		} else if (type & MEMORY_MANAGEMENT_REG) {
			subtype_bit = 8;
		} else if (type & SEGMENT_REG) {
			subtype_bit = 9;
		}
	} else if (type & MEMORY_TYPE) {
		type_bit = 2;
		switch (arg.Memory.Scale) {
		case 1:
			subtype_bit = 0;
			break;
		case 2:
			subtype_bit = 1;
			break;
		case 3:
			subtype_bit = 2;
			break;
		case 8:
			subtype_bit = 3;
			break;
		}
		subtype_bit = subtype_bit << 2;

		// Memory.Displacement is stored only partially, should be checked after!
		subtype_bit += (arg.Memory.Displacement % 4);
	} else if (type & CONSTANT_TYPE) {
		type_bit = 3;
		if (type & RELATIVE_) {
			subtype_bit = 1;
		} else if (type & ABSOLUTE_) {
			subtype_bit = 2;
		}
	}

	return (size_bit << 6) | (type_bit << 4) | subtype_bit;
}
