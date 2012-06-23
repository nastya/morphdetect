#ifndef __BLOCK_H
#define __BLOCK_H
#include <set>
#include <unordered_set>
#include <vector>
#include <string>
#include <fstream>
#include <beaengine/BeaEngine.h>
#include "normalizer.h"
#include <string>
#include "cache.h"
#include "instructionQueue.h"
using namespace std;

class Normalizer;

class BlockInfo
{
public:
	BlockInfo(Cache* cache, UIntPtr data_start, UIntPtr data_end, UIntPtr entry_point, bool resp);
	BlockInfo(BlockInfo* parent, UIntPtr entry_point);
	~BlockInfo();
	void generateDot(string filename, vector <BlockInfo*>* roots = NULL);
	void process();
	BlockInfo* removeJumpsOnly();
	BlockInfo* removeJxJnx();
	void mergeBlocks();
	void dfs(set<BlockInfo*> &done);
	void clearOppositeInstructions();
	void normalize();
	bool isMarked(UIntPtr);
	void copyMark(BlockInfo*);
	InstructionQueue getInstructions();
	void getEIPSPasse(unordered_set<int> *s);
private:
	struct SubBlock 
	{
		SubBlock(UIntPtr e, int s): entry_point(e), size(s)
		{
		}
		UIntPtr entry_point;
		int size;
	};
	
	vector<BlockInfo::SubBlock>::iterator cutSubBlock(vector<BlockInfo::SubBlock>::iterator it, UIntPtr addr, int len);

	void clearOppositeInstructions(set<BlockInfo*> &done);
	
	void removeJumpsInside();	
	void mergeBlocks(set<BlockInfo*> &done);
	
	bool isDirectJx(UIntPtr* addr, int* type);
	BlockInfo* removeJxJnx(set<BlockInfo*> &done);
	
	BlockInfo* removeJumpsOnly(set<BlockInfo*> &done);
	
	void addBranch(UIntPtr, UIntPtr);
	BlockInfo* divideBlock(UIntPtr);
	
	void generateDot(set<BlockInfo*> &done, ostream &out);
	
	void getEIPSPasse(set<BlockInfo*> &done, unordered_set<int> *s);
	inline void getEIPSPasseOne(unordered_set<int> *s);

	UIntPtr _data_start, _data_end;
	set <BlockInfo*> _to;
	set <BlockInfo*> _from;
	bool _first_block;
	BlockInfo** _mark;
	Cache* _cache;
	vector <SubBlock> _subBlocks;
	Normalizer* _normalizer;
	bool _markResponsable;
	bool _dirtyDelete;
};

#endif // __BLOCK_H
