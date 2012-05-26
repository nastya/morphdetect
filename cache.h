#ifndef __CACHE_H
#define __CACHE_H
#include <beaengine/BeaEngine.h>
#include <map>

using namespace std;

struct Disassembler
{
	DISASM disas;
	int len;
};

class Cache
{
public:
	DISASM* getInstruction(UIntPtr addr, int *length = NULL);
	void clear();
private:
	map<UIntPtr, Disassembler> m;
};

#endif //__CACHE_H