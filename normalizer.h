#ifndef __NORMALIZER_H
#define __NORMALIZER_H
#include <set>
#include "block.h"
using namespace std;

class BlockInfo;

class Normalizer
{
public:
	Normalizer(BlockInfo*);
	void remember(BlockInfo*);
	void forget(BlockInfo*);
	void normalize();
	void changeRoot(BlockInfo*);
private:
	bool _running;
	set <BlockInfo*> _known;
	BlockInfo* _root;
};

#endif //__NORMALIZER_H
