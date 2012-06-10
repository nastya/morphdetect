#ifndef __MEMORY_BLOCK_H
#define __MEMORY_BLOCK_H

#include <unistd.h>
using namespace std;

struct MemoryBlock
{
	MemoryBlock(const MemoryBlock &memoryBlock);
	MemoryBlock();
	MemoryBlock(int size, const unsigned char *d = NULL);
	virtual ~MemoryBlock();

	const unsigned char *data;
	int size;
protected:
	bool _del_flag;
};

#endif