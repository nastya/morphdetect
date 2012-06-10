#include "sample.h"
#include <finddecryptor/reader.h>
#include <cstring>

Sample::Sample(const Sample &sample)
 : MemoryBlock(sample), name(sample.name)
{}

Sample::Sample(string n, string filePath)
{
	name = n;
	Reader reader;
	reader.load(filePath.c_str());
	size = reader.size();
	data = new unsigned char[size];
	memcpy((unsigned char *) data, reader.pointer(), size);
	_del_flag = true;
}

Sample::Sample(string n, int ds, unsigned char *d)
 : MemoryBlock(ds, d), name(n)
{}
