#ifndef __SAMPLE_H
#define __SAMPLE_H

#include "memoryBlock.h"
#include <string>

using namespace std;

struct Sample: public MemoryBlock
{
	Sample(const Sample &sample);
	Sample(string name, string filePath);
	Sample(string name, int size, unsigned char *data = NULL);
	string name;
};

#endif