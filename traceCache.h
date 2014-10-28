#ifndef __TRACE_CACHE_H
#define __TRACE_CACHE_H

#include <beaengine/BeaEngine.h>
#include <unordered_map>
#include <queue>

namespace detect_similar
{

using namespace std;

struct TraceDisassembler
{
	DISASM disas;
	int len;
	unsigned char buf[10];
};

class TraceCache
{
public:
	DISASM* getInstruction(int eip, void *addr, int *length = NULL);
	void clear();
private:
	unordered_map<int, TraceDisassembler> m;
	queue<DISASM> extra;
};

} //namespace detect_similar

#endif //__CACHE_H