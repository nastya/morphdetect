#include "memoryBlock.h"
#include <cstring>
#include <iostream>

MemoryBlock::MemoryBlock(const MemoryBlock &memoryBlock)
 : size(memoryBlock.size), _del_flag(true), statByte(NULL)
{
	data = new unsigned char [size];
	memcpy((unsigned char *) data, memoryBlock.data, size);
}

MemoryBlock::MemoryBlock(int ds, const unsigned char *d)
 : size(ds), _del_flag(true), statByte(NULL)
{
	data = new unsigned char [size];
	if (d != NULL)
		memcpy((unsigned char *) data, d, size);
}

MemoryBlock::MemoryBlock()
 : _del_flag(false), statByte(NULL)
{
}

MemoryBlock::~MemoryBlock()
{
	if (_del_flag)
		delete[] data;
	if (statByte != NULL)
		delete[] statByte;
}

void MemoryBlock::link(const unsigned char *data, size_t data_size)
{
	if (_del_flag)
		delete[] this->data;
	statBlock.clear();
	if (statByte != NULL)
		delete[] statByte;
	statByte = NULL;
	this->data = data;
	this->size = data_size;
	_del_flag = false;
}

/**
 * Shellcode is generally much smaller than the current block.
 */
size_t MemoryBlock::compareNgram(MemoryBlock &shellcode)
{
	checkStatBlock();
	shellcode.checkStatBlock();

	size_t count = 0;
	for (auto &pair : shellcode.statBlock)
		if (statBlock.count(pair.first))
			count += min(pair.second, statBlock[pair.first]);
	return count;
}

void MemoryBlock::checkStatBlock()
{
	if (statBlock.size() > 0)
		return;
	const unsigned char *b = data;
	for (size_t i = 0; i <= size - sizeof(mblock); i++, b++)
		statBlock[*(const mblock *) b]++;
}

/**
 * Shellcode is generally much smaller than the current block.
 */
size_t MemoryBlock::compareDiff(MemoryBlock &shellcode, float threshold)
{
	if ((shellcode.size == 0) || (size == 0)) {
		cerr << "WHOOPS! " << shellcode.size << " " << size << endl;
		return 0;
	}
	size_t step_size = shellcode.size * 2;
	if (size <= 2 * step_size) {
		if (!shellcode.possibleDiff(data, size, threshold))
			return 0;
		return CompareUtils::longest_common_subsequence(data, size, shellcode.data, shellcode.size);
	}
	size_t last = size - 2 * step_size;

	size_t res = 0;
	for (size_t i = 0; i < size - step_size; i += step_size) {
		const mbyte *data_start = data + min(i, last);
		size_t data_size = 2 * step_size;
		if (!shellcode.possibleDiff(data_start, data_size, threshold))
			continue;
		res = max(res, CompareUtils::longest_common_subsequence(data_start, data_size, shellcode.data, shellcode.size));
	}
	return res;
}

bool MemoryBlock::possibleDiff(const unsigned char *data_start, size_t data_size, float threshold)
{
	checkStatByte();

	uint32_t stat_data[256] = {0};
	for (size_t i = 0; i < data_size; i++)
		stat_data[data_start[i]]++;

	int total = 0;
	for (size_t i = 0; i < 256; i++)
		total += min(statByte[i], stat_data[i]);

	return total >= threshold * size;
}

void MemoryBlock::checkStatByte()
{
	if (statByte != NULL)
		return;
	statByte = new uint32_t[256];
	memset(statByte, 0, 256 * sizeof(uint32_t));
	for (size_t i = 0; i < size; i++)
		statByte[data[i]]++;
}
