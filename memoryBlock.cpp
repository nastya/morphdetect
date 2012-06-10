#include "memoryBlock.h"
#include <cstring>

MemoryBlock::MemoryBlock(const MemoryBlock &memoryBlock)
 : size(memoryBlock.size), _del_flag(true)
{
	data = new unsigned char [size];
	memcpy((unsigned char *) data, memoryBlock.data, size);
}

MemoryBlock::MemoryBlock(int ds, const unsigned char *d)
 : size(ds), _del_flag(true)
{
	data = new unsigned char [size];
	if (d != NULL)
		memcpy((unsigned char *) data, d, size);
}

MemoryBlock::MemoryBlock()
 : _del_flag(false)
{
}

MemoryBlock::~MemoryBlock()
{
	if (_del_flag)
		delete[] data;
}