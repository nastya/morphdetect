#ifndef __SAMPLE_H
#define __SAMPLE_H

#include "memoryBlock.h"
#include <string>

namespace detect_similar
{

using namespace std;

struct Sample: public MemoryBlock
{
	Sample(const Sample &sample);
	Sample(string name, string filePath);
	Sample(string name, int size, unsigned char *data = NULL);
	string name;
};

} //namespace detect_similar

#endif