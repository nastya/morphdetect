#ifndef __MEMORY_BLOCK_H
#define __MEMORY_BLOCK_H

#include <unistd.h>
#include "compareUtils.h"

namespace detect_similar
{

using namespace std;

struct MemoryBlock
{
	MemoryBlock(const MemoryBlock &memoryBlock);
	MemoryBlock();
	MemoryBlock(int size, const unsigned char *d = NULL);
	virtual ~MemoryBlock();
	size_t compareDiff(MemoryBlock &shellcode, float threshold);
	size_t compareNgram(MemoryBlock &shellcode);
	void link(const unsigned char *data, size_t data_size);

	const unsigned char *data;
	unsigned int size;
protected:
public:
	bool possibleDiff(const unsigned char *data, size_t data_size, float threshold);
	void checkStatBlock();
	void checkStatByte();
	bool _del_flag;
	uint32_t *statByte;
	unordered_map<mblock, size_t> statBlock;
};

} //namespace detect_similar

#endif