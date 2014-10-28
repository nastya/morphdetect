#ifndef __CACHE_H
#define __CACHE_H
#include <beaengine/BeaEngine.h>
#include <unordered_map>

namespace detect_similar
{

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
	unordered_map<UIntPtr, Disassembler> m;
};

} //namespace detect_similar

#endif //__CACHE_H