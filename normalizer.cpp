#include "normalizer.h"
#include <assert.h>
#include <iostream>

Normalizer::Normalizer(BlockInfo* root): _running(false), _root(root)
{
}

void Normalizer::remember(BlockInfo* block)
{
	assert(_known.count(block) == 0);
	_known.insert(block);
}

void Normalizer::forget(BlockInfo* block)
{
	assert(_known.count(block) > 0);
	_known.erase(block);
}

void Normalizer::changeRoot(BlockInfo* newRoot)
{
	_root = newRoot;
}

void Normalizer::normalize()
{
	if (_running)
		return;
	_running = true;
	
	/*
	cout<<"Root ="<<(void*)_root<<endl;
	cout<<"Known blocks: " << _known.size() << endl;
	for (auto it = _known.begin(); it != _known.end(); ++it)
		cout<<(void *)(*it)<<" ";
	cout<<endl;
	*/
	set <BlockInfo*> reached_blocks;
	_root->dfs(&reached_blocks);
	/*
	cout<<"Reached blocks (" << reached_blocks.size() << ") :";
	for (auto it = reached_blocks.begin(); it != reached_blocks.end(); ++it)
		cout << " " << (void *)(*it);
	cout<<endl;
	*/
	set<BlockInfo*> known_before = _known;
	for (auto it = known_before.begin(); it != known_before.end(); ++it)
	{
		if (!reached_blocks.count(*it))
			delete (*it);
	}
	_running = false;
}