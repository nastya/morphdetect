#include "block.h"
#include "wrappers.h"
#include <string.h>
#include <iostream>
#include <assert.h>

#define DFS(function, done, ...) \
	done.insert(this); \
	for (auto it = _to.begin(); it != _to.end(); ++it) \
		if (!done.count(*it)) \
			(*it)->function(done, ##__VA_ARGS__);

#define DFS_CLONE(function, done, ...) \
	done.insert(this); \
	auto copy_to = _to; \
	for (auto it = copy_to.begin(); it != copy_to.end(); ++it) \
		if (!done.count(*it)) \
			(*it)->function(done, ##__VA_ARGS__);

#define COMPARE(a, b, a0, b0) ((strcmp(a, a0) == 0) && (strcmp(b, b0) == 0))
#define EQCOMPARE(a, b, a0) COMPARE(a, b, a0, a0)
#define BICOMPARE(a, b, a0, b0) (COMPARE(a, b, a0, b0) || COMPARE(a, b, b0, a0))

BlockInfo::BlockInfo(Cache* cache, UIntPtr data_start, UIntPtr data_end, UIntPtr entry_point)
	:_data_start(data_start), _data_end(data_end), _first_block(true), _cache(cache),
	_dirtyDelete(false)
{
	_subBlocks.push_back(SubBlock((entry_point == 0) ? data_start : entry_point, 0));

	_mark = new BlockInfo* [data_end - data_start + 1];
#if NULL==0
	memset(_mark, 0, sizeof(BlockInfo*) * (data_end - data_start + 1));
#else
	for (unsigned int i = 0; i <= _data_end - _data_start; i++)
		_mark[i] = NULL;
#endif

	_normalizer = new Normalizer(this);
	_normalizer->remember(this);
}

BlockInfo::BlockInfo(BlockInfo* parent, UIntPtr entry_point)
	: _data_start(parent->_data_start), _data_end(parent->_data_end),
	_first_block(false), _mark(parent->_mark), _cache(parent->_cache), _normalizer(parent->_normalizer),
	_dirtyDelete(false)
{
	_from.insert(parent);
	parent->_to.insert(this);
	_subBlocks.push_back(SubBlock(entry_point, 0));
	_normalizer->remember(this);
}

BlockInfo::~BlockInfo()
{
	//cerr<<"Deleting..."<<(void*)this<<endl;
	if (_dirtyDelete)
		return;

	if (_first_block) {
		// Fast delete everything using _dirtyDelete
		_normalizer->forget(this);
		const unordered_set <BlockInfo*> *all = _normalizer->known();
		for (auto block = all->begin(); block != all->end(); ++block)
		{
			(*block)->_dirtyDelete = true;
			delete (*block);
		}
		delete [] _mark;
		delete _normalizer;
		return;
	}

	for (auto it = _from.begin(); it != _from.end(); ++it)
		(*it)->_to.erase(this);
	for (auto it = _to.begin(); it != _to.end(); ++it)
		(*it)->_from.erase(this);
	_to.clear();
	_from.clear();
	_normalizer->forget(this);
	_normalizer->normalize();
}

InstructionQueue BlockInfo::getInstructions()
{
	InstructionQueue instructions;
	set <BlockInfo*> queue;
	set <BlockInfo*> extraQueue;
	queue.insert(this);
	extraQueue.insert(this);
	set <BlockInfo*> marked;
	BlockInfo* element;
	while (!queue.empty() || !extraQueue.empty())
	{
		if (!queue.empty())
			element = *queue.begin();
		else
			element = *extraQueue.begin();
		marked.insert(element);
		queue.erase(element);
		extraQueue.erase(element);
		for (auto it = element->_subBlocks.begin(); it != element->_subBlocks.end(); ++it)
		{
			int len;
			for (UIntPtr eip = it->entry_point; eip < it->entry_point + it->size; eip += len)
			{
				DISASM *disasm = _cache->getInstruction(eip, &len);
				if (len == UNKNOWN_OPCODE)
				{
					//cerr << "UNKNOWN_OPCODE" << endl;
					break;
				}
				if (	!disasm->Instruction.BranchType &&
					disasm->Instruction.Opcode != 0x00 && // 0x00 = probably junk
					disasm->Instruction.Opcode != 0x90) // 0x90 = NOP
					instructions.push_back(InstructionInfo(disasm, len));
			}
		}
		for (auto it = element->_to.begin(); it != element->_to.end(); ++it)
		{
			if (!marked.count(*it))
			{
				extraQueue.insert(*it);
				bool add = true;
				for (auto par = (*it)->_from.begin(); par != (*it)->_from.end(); ++par)
				{
					if ((*par != *it) && !(marked.count(*par)))
					{
						add = false;
						break;
					}
				}
				if (add)
				{
					queue.insert(*it);
				}
			}
		}
	}
	return instructions;
}

bool BlockInfo::isMarked(UIntPtr addr)
{
	return (_mark[addr - _data_start] != NULL);
}

void BlockInfo::copyMark(BlockInfo* bl)
{
	_mark = bl->_mark;
	/*for (int i = 0; i < _data_end - _data_start; i++)
		_mark[i] = bl->_mark[i];*/
}

void BlockInfo::generateDot(string filename, vector <BlockInfo*>* roots)
{
	ofstream out(filename.c_str());
	out << "digraph CFG {" << endl;
	set <BlockInfo*> done;
	if (roots == NULL)
		generateDot(done, out);
	else
	{
		for (auto it = roots->begin(); it != roots->end(); ++it)
		{
			(*it)->generateDot(done, out);
		}
	}
	out << "}";
	out.close();
}
void BlockInfo::generateDot(set<BlockInfo*> &done, ostream &out)
{
	out<< "\t" << "b" << (void *) this <<" [ shape=box, label=\"";
//	out<<(void*)this << " block"<<"\\n";
	for (auto it = _subBlocks.begin(); it != _subBlocks.end(); ++it)
	{
		int len;
		for (UIntPtr eip = it->entry_point; eip < it->entry_point + it->size; eip += len)
		{
			DISASM *disasm = _cache->getInstruction(eip, &len);
			out << disasm->CompleteInstr << "\\n";
		}
	}
	out<<"\"]"<<endl;
	for (auto it = _to.begin(); it != _to.end(); ++it)
	{
		out << "\t" << "b" << (void *) this << " -> b" << (void *) *it << endl;
	}
	DFS(generateDot, done, out)
}

void BlockInfo::getEIPSPasse(unordered_set<int> *s)
{
	if (_first_block) {
		const unordered_set <BlockInfo*> *all = _normalizer->known();
		for (auto block = all->begin(); block != all->end(); ++block)
			(*block)->getEIPSPasseOne(s);
	} else {
		set <BlockInfo*> done;
		getEIPSPasse(done, s);
	}
}

void BlockInfo::getEIPSPasse(set<BlockInfo*> &done, unordered_set<int> *s)
{
	getEIPSPasseOne(s);
	DFS(getEIPSPasse, done, s)
}

void BlockInfo::getEIPSPasseOne(unordered_set<int> *s)
{
	for (auto it = _subBlocks.begin(); it != _subBlocks.end(); ++it)
	{
		int len;
		for (UIntPtr eip = it->entry_point; eip < it->entry_point + it->size; eip += len)
		{
			s->insert(eip - _data_start);
			_cache->getInstruction(eip, &len);
		}
	}
}

BlockInfo* BlockInfo::divideBlock(UIntPtr addr)
{
	assert(_subBlocks.size() == 1);
	
	if (addr == _subBlocks[0].entry_point)
		return this;
	BlockInfo *oldBlock = this;
	BlockInfo *newBlock = new BlockInfo(oldBlock, addr);
	// Переносим _to
	newBlock->_to = oldBlock->_to;
	newBlock->_to.erase(newBlock);
	oldBlock->_to.clear();
	oldBlock->_to.insert(newBlock);
	// поменять всем из newBlock->_to значения в _from с _oldBlock на _newBlock
	for (auto it = newBlock->_to.begin(); it != newBlock->_to.end(); ++it)
	{
		(*it)->_from.erase(oldBlock);
		(*it)->_from.insert(newBlock);
	}

	// Устанавливаем размер
	newBlock->_subBlocks[0].size = oldBlock->_subBlocks[0].size - (addr - oldBlock->_subBlocks[0].entry_point);
	oldBlock->_subBlocks[0].size = addr - oldBlock->_subBlocks[0].entry_point;

	// меняем mark?
	// Идём от addr и вперёд, пока не случится так, что на 10 байтах подряж не будет указателя на старый блок

	for (unsigned int i = addr - _data_start; i < _data_end - _data_start;)
	{
		_mark[i] = newBlock;
		bool ok = false;
		for(unsigned int j = 1; (j <= 10) && (i + j < _data_end - _data_start); j++)
			if (_mark[i+j] == oldBlock)
			{
				i+=j;
				ok = true;
				break;
			}
		if (!ok) break;
	}
	return newBlock;
}

void BlockInfo::addBranch(UIntPtr addr, UIntPtr addr_from)
{
	if (!(addr >= _data_start && addr < _data_end))
		return;
	BlockInfo* oldBlock = _mark[addr - _data_start];
	if (oldBlock != NULL)
	{
		assert(oldBlock->_subBlocks.size() == 1);
		if (oldBlock->_subBlocks[0].entry_point == addr)
		{
			_to.insert(oldBlock);
			oldBlock->_from.insert(this);
		}
		else
		{
			BlockInfo* newBlock = oldBlock->divideBlock(addr);
			newBlock->_from.insert(_mark[addr_from - _data_start]);
			_mark[addr_from - _data_start]->_to.insert(newBlock);
		}
	}
	else
	{
		BlockInfo* child = new BlockInfo(this, addr);
		child->process();
	}	
}

void BlockInfo::process()
{
	//cerr << "Processing " << (void*) this << endl;
	assert(_subBlocks.size() == 1);
	assert(_subBlocks[0].size == 0);

	//cerr << "Entry point: " << _subBlocks[0].entry_point << endl;
	int len;
	UIntPtr eip = _subBlocks[0].entry_point;
	for (; eip < _data_end; eip += len)
	{
		if (_mark[eip - _data_start] != NULL)
		{
			BlockInfo* oldBlock = _mark[eip - _data_start];
			//cerr << "went to block" << (void *) oldBlock << "at the point" << eip << endl;
			BlockInfo* newBlock = oldBlock->divideBlock(eip);
			//cerr << "this block after division" << (void *) newBlock << endl;
			_subBlocks[0].size = eip - _subBlocks[0].entry_point;
			newBlock->_from.insert(this);
			_to.insert(newBlock);
			return;
		}
		_mark[eip - _data_start] = this;

		DISASM *disasm = _cache->getInstruction(eip, &len);

		if (len == UNKNOWN_OPCODE)
		{
			//cerr << "ERROR" << endl;
			break;
		}

		if ((disasm->Instruction.Category & 0xFFFF0000) == SYSTEM_INSTRUCTION)
		{
			//TODO: check if it is really unuseful and not allowed
			break;
		}

		//cerr << disasm->CompleteInstr << endl;
		if (disasm->Instruction.BranchType)
		{
			//cerr<<"Branch Type"<<endl;
			_subBlocks[0].size = eip + (UIntPtr) len - _subBlocks[0].entry_point;
			UIntPtr addrToJump = disasm->Instruction.AddrValue;
			UIntPtr curAddr = eip;
			if (disasm->Instruction.AddrValue == 0)
				return;
			switch (disasm->Instruction.BranchType)
			{
				case CallType:
				case JmpType:
					_mark[curAddr - _data_start]->addBranch(addrToJump, curAddr);
					break;
				case RetType:
					//cerr<<"Ret type"<<endl;
					break;
				default:
					_mark[curAddr - _data_start]->addBranch(curAddr + (UIntPtr)len, curAddr);
					_mark[curAddr - _data_start]->addBranch(addrToJump, curAddr);
			}
			return;
		}
	}
	_subBlocks[0].size = eip - _subBlocks[0].entry_point;
	//cerr<<"Reached the end"<<endl;
}

void BlockInfo::dfs(set<BlockInfo*> &done)
{
	DFS(dfs, done)
}

void BlockInfo::mergeBlocks()
{
	set <BlockInfo *> done;
	mergeBlocks(done);
	_normalizer->normalize();
}

void BlockInfo::clearOppositeInstructions()
{
	set <BlockInfo*> done;
	clearOppositeInstructions(done);
}

vector<BlockInfo::SubBlock>::iterator BlockInfo::cutSubBlock(vector<BlockInfo::SubBlock>::iterator it, 
							     UIntPtr addr, int len)
{
	if (addr != it->entry_point)
	{
		if (addr + (UIntPtr) len < it->entry_point + it->size)
		{
			int newsize = it->size - (addr - it->entry_point) - len;
			it->size = addr - it->entry_point;
			++it;
			return _subBlocks.insert(it, SubBlock(addr + (UIntPtr)len, newsize));
		}
		else
		{
			it->size = addr - it->entry_point;
			return ++it;
		}
	}
	else
	{
		if (addr + (UIntPtr) len < it->entry_point + it->size)
		{
			it->entry_point = addr + (UIntPtr) len;
			return ++it;
		}
		else
		{
			return _subBlocks.erase(it);
		}
	}
}

void BlockInfo::clearOppositeInstructions(set<BlockInfo*> &done)
{
	DISASM *prev = NULL;
	int prev_len = 0;
	UIntPtr prev_addr = 0;
	auto prev_subblock = _subBlocks.begin();
	for (auto it = _subBlocks.begin(); it != _subBlocks.end(); )
	{
		bool it_changed = false;
		int len;
		for (UIntPtr eip = it->entry_point; eip < it->entry_point + it->size; eip += len)
		{
			DISASM *disasm = _cache->getInstruction(eip, &len);

			if (	prev != NULL &&
				strcmp(prev->Argument1.ArgMnemonic, disasm->Argument1.ArgMnemonic) == 0 &&
				strcmp(prev->Argument2.ArgMnemonic, disasm->Argument2.ArgMnemonic) == 0 &&
				strcmp(prev->Argument3.ArgMnemonic, disasm->Argument3.ArgMnemonic) == 0 &&
				(
				BICOMPARE(prev->Instruction.Mnemonic, disasm->Instruction.Mnemonic, "add ", "sub ") ||
				BICOMPARE(prev->Instruction.Mnemonic, disasm->Instruction.Mnemonic, "ror ", "rol ") ||
				EQCOMPARE(prev->Instruction.Mnemonic, disasm->Instruction.Mnemonic, "xor ") ||
				EQCOMPARE(prev->Instruction.Mnemonic, disasm->Instruction.Mnemonic, "xchg ") ||
				EQCOMPARE(prev->Instruction.Mnemonic, disasm->Instruction.Mnemonic, "btc ")
				))
			{
				////cerr<<"Cutting from block"<<(void *)this<<endl;
				if (prev_subblock == it)
				{
					it = cutSubBlock(it, prev_addr, prev_len + len);
				}
				else
				{
					it = cutSubBlock(prev_subblock, prev_addr, prev_len);
					it = cutSubBlock(it, eip, len);
				}
				prev = NULL;
				prev_len = 0;
				prev_addr = 0;
				prev_subblock = it;
				it_changed = true;
				break;
			}
			prev = disasm;
			prev_len = len;
			prev_addr = eip;
			prev_subblock = it;
		}
		if (!it_changed)
			++it;
	}
	DFS(clearOppositeInstructions, done)
}

void BlockInfo::mergeBlocks(set<BlockInfo*> &done)
{
	removeJumpsInside();
	if (_from.size() == 1)
	{
		BlockInfo* parent = (*_from.begin());
		if (parent->_to.size() == 1)
		{
			parent->_to = _to;
			for (auto it = _to.begin(); it != _to.end(); ++it)
			{
				(*it)->_from.erase(this);
				(*it)->_from.insert(parent);
			}
			parent->_subBlocks.push_back(SubBlock(_subBlocks[0].entry_point, _subBlocks[0].size));
			_to.clear();
			_from.clear();
			set <BlockInfo*> children = parent->_to;
			for (auto it = children.begin(); it != children.end(); ++it)
				if (!done.count(*it))
					(*it)->mergeBlocks(done);
			return;
		}
	}
	DFS_CLONE(mergeBlocks, done)
}

bool BlockInfo::isDirectJx(UIntPtr* addr, int* type)
{
	assert(_subBlocks.size() == 1);
	int count = 0;
	bool jump = false;
	int len;
	for (UIntPtr eip = _subBlocks[0].entry_point; eip < _subBlocks[0].entry_point + _subBlocks[0].size; eip += len)
	{
		DISASM *disasm = _cache->getInstruction(eip, &len);
		if (disasm->Instruction.BranchType && disasm->Instruction.AddrValue != 0 &&
			disasm->Instruction.BranchType != CallType && disasm->Instruction.BranchType != RetType &&
			disasm->Instruction.BranchType != JECXZ && disasm->Instruction.BranchType != JmpType)
		{
			jump = true;
			(*addr) = disasm->Instruction.AddrValue;
			(*type) = disasm->Instruction.BranchType;
		}
		count++;
	}
	if (count == 0 || ((count == 1) && jump) )
	{
		return true;
	}
	else
	{
		return false;
	}
}

void BlockInfo::normalize()
{
	_normalizer->normalize();
}

BlockInfo* BlockInfo::removeJxJnx()
{
	set <BlockInfo*> done;
	BlockInfo* first = removeJxJnx(done);
	if (first != NULL)
	{
		_normalizer->changeRoot(first);
	}
	return first;
}


BlockInfo* BlockInfo::removeJxJnx(set<BlockInfo*> &done)
{
	UIntPtr addrJx, addrJnx;
	int jxtype, jnxtype;
	if (isDirectJx(&addrJx, &jxtype))
	{
		bool caseJxJnx = false;
		BlockInfo *suc_block = NULL;
		for (auto it_jnx = _to.begin(); it_jnx != _to.end(); ++it_jnx)
		{
			if ((*it_jnx)->isDirectJx(&addrJnx,&jnxtype) && (jxtype == -jnxtype) && (addrJx == addrJnx) &&
				(*it_jnx)->_from.size() == 1)
			{
				caseJxJnx = true;
			}
			else
			{
				suc_block = (*it_jnx);
			}
		}
		if (caseJxJnx && suc_block != NULL)
		{
			for (auto it_par = _from.begin(); it_par != _from.end(); ++it_par)
			{
				(*it_par)->_to.erase(this);
				(*it_par)->_to.insert(suc_block);
				suc_block->_from.insert(*it_par);
			}
			_from.clear();
			if (_first_block)
			{
				suc_block->_first_block = true;
				_first_block = false;
			}
			return suc_block->removeJxJnx(done);	
		}
	}
	DFS_CLONE(removeJxJnx, done)
	return this;
}

void BlockInfo::removeJumpsInside()
{
	int len;
	for (UIntPtr eip = _subBlocks[0].entry_point; eip < _subBlocks[0].entry_point + _subBlocks[0].size; eip += len)
	{
		DISASM *disasm = _cache->getInstruction(eip, &len);
		if (disasm->Instruction.BranchType == JmpType && disasm->Instruction.AddrValue != 0)
		{
			_subBlocks[0].size = eip - _subBlocks[0].entry_point;
			break;
		}
	}
}

BlockInfo* BlockInfo::removeJumpsOnly()
{
	set <BlockInfo*> done;
	BlockInfo* first = removeJumpsOnly(done);
	if (first!=NULL)
		_normalizer->changeRoot(first);
	return (first != NULL) ? first : this;
}


BlockInfo* BlockInfo::removeJumpsOnly(set<BlockInfo*> &done)
{
	assert(_subBlocks.size() == 1);
	//assert(_entry_points.size() == 1);

	if ( _to.size() <= 1)
	/*if (((_from.size() == 1 && (*_from.begin())->_to.size() == 1) || _from.size() == 0) &&
		((_to.size() == 1 && (*_to.begin())->_from.size() == 1) || _to.size() == 0))*/
	{
		int count = 0;
		bool jump = false;
		int len;
		for (UIntPtr eip = _subBlocks[0].entry_point; eip < _subBlocks[0].entry_point + _subBlocks[0].size; eip += len)
		{
			DISASM *disasm = _cache->getInstruction(eip, &len);
			if (disasm->Instruction.BranchType == JmpType && disasm->Instruction.AddrValue != 0)
			{
				jump = true;
			}
			count++;
		}
		if ((count == 1 && jump) || (count == 0))
		{
			if (_from.size() == 0 && _to.size() == 0)
			{
				return this;
			}
			if (_from.size() == 0 && _to.size() != 0)
			{
				BlockInfo* child = *(_to.begin());
				if (_first_block)
				{
					child->_first_block = true;
					_first_block = false;
				}
				child->_from.erase(this);
				_to.clear();
				return child->removeJumpsOnly(done);
			}
			if (_from.size() != 0 && _to.size() != 0 && !_first_block)
			{
				BlockInfo* child = *(_to.begin());
				child->_from.erase(this);
				for (auto it = _from.begin(); it != _from.end(); ++it)
				{
					BlockInfo* parent = (*it);
					parent->_to.erase(this);
					parent->_to.insert(child);
					child->_from.insert(parent);
				}
				_to.clear();
				_from.clear();
				return child->removeJumpsOnly(done);
				
			}
			if (_from.size() != 0 && _to.size() == 0)
			{
				for (auto it = _from.begin(); it != _from.end(); ++it)
				{
					BlockInfo* parent = (*it);
					parent->_to.erase(this);
				}
				_from.clear();
				return NULL;
			}
		}
	}
	DFS_CLONE(removeJumpsOnly, done)
	return this;
}
