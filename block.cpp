#include "block.h"
#include <string.h>
#include <iostream>
#include <assert.h>


BlockInfo::BlockInfo(DISASM* disasm, UIntPtr data_start, UIntPtr data_end, UIntPtr entry_point, bool resp)
	:_data_start(data_start), _data_end(data_end), _first_block(true), _disasm(disasm)
{
	_markResponsable = resp;
	_subBlocks.push_back(SubBlock((entry_point == 0) ? data_start : entry_point, 0));
	if (_markResponsable)
	{
		_mark = new BlockInfo* [data_end - data_start + 1];
		for (unsigned int i = 0; i < _data_end - _data_start; i++)
			_mark[i] = NULL;
	}
	_normalizer = new Normalizer(this);
	_normalizer->remember(this);
}

BlockInfo::BlockInfo(BlockInfo* parent, UIntPtr entry_point)
	: _data_start(parent->_data_start), _data_end(parent->_data_end),
	_first_block(false), _mark(parent->_mark), _disasm(parent->_disasm), _normalizer(parent->_normalizer),
	_markResponsable(false)
{
	_from.insert(parent);
	parent->_to.insert(this);
	_subBlocks.push_back(SubBlock(entry_point, 0));
	_normalizer->remember(this);
}

BlockInfo::~BlockInfo()
{
	//cerr<<"Deleting..."<<(void*)this<<endl;
	for (set <BlockInfo*>::iterator it = _from.begin(); it != _from.end(); ++it)
	{
		(*it)->_to.erase(this);
	}
	for (set <BlockInfo*>::iterator it = _to.begin(); it != _to.end(); ++it)
	{
		(*it)->_from.erase(this);
	}
	_normalizer->forget(this);
	_normalizer->normalize();
	if (_first_block)
	{
		if (_markResponsable)
			delete [] _mark;
		delete _normalizer;
	}
}

int BlockInfo::getProcessed(unsigned char*s)
{
	set <BlockInfo*> queue;
	set <BlockInfo*> extraQueue;
	queue.insert(this);
	extraQueue.insert(this);
	set <BlockInfo*> marked;
	int len = 0;
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
		for (vector<SubBlock>::iterator it = element->_subBlocks.begin(); it != element->_subBlocks.end(); ++it)
		{
			memcpy(s + len, (unsigned char*)(*it).entry_point, (*it).size);
			len += (*it).size;
		}
		for (set<BlockInfo*>::iterator it = element->_to.begin(); it != element->_to.end(); ++it)
		{
			if (!marked.count(*it))
			{
				extraQueue.insert(*it);
				bool add = true;
				for (set<BlockInfo*>::iterator par = (*it)->_from.begin(); par != (*it)->_from.end(); ++par)
				{
					if (!(*par == *it) && !(marked.count(*par)))
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
	return len;
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
		generateDot(out, &done);
	else
	{
		for (vector <BlockInfo*>::iterator it = roots->begin(); it != roots->end(); ++it)
		{
			(*it)->generateDot(out, &done);
		}
	}
	out << "}";
	out.close();
}
void BlockInfo::generateDot(ostream& out, set<BlockInfo *> *done)
{
	out<< "\t" << "b" << (void *) this <<" [ shape=box, label=\"";
//	out<<(void*)this << " block"<<"\\n";
	for (vector <SubBlock>::iterator it = _subBlocks.begin(); it != _subBlocks.end(); ++it)
	{
		(void) memset (&(*_disasm), 0, sizeof(DISASM));
		(*_disasm).EIP = (*it).entry_point;
		while ((*_disasm).EIP < (*it).entry_point + (UIntPtr)(*it).size)
		{
			int len = Disasm(&(*_disasm));
			out<< (*_disasm).CompleteInstr<< "\\n";
			(*_disasm).EIP = (*_disasm).EIP + (UIntPtr) len;
		}
	}
	out<<"\"]"<<endl;
	for (set <BlockInfo*>::iterator it = _to.begin(); it != _to.end(); ++it)
	{
		out << "\t" << "b" << (void *) this << " -> b" << (void *) *it << endl;
	}
	done->insert(this);
	for (set <BlockInfo*>::iterator it = _to.begin(); it != _to.end(); ++it)
	{
		if (!done->count(*it))
			(*it)->generateDot(out, done);
	}
}

void BlockInfo::getEIPSPasse(set <int>* s)
{
	set <BlockInfo*> done;
	_getEIPSPasse(s, &done);
}

void BlockInfo::_getEIPSPasse(set <int>* s, set <BlockInfo*> *done)
{
	for (vector <SubBlock>::iterator it = _subBlocks.begin(); it != _subBlocks.end(); ++it)
	{
		(void) memset (&(*_disasm), 0, sizeof(DISASM));
		(*_disasm).EIP = (*it).entry_point;
		while ((*_disasm).EIP < (*it).entry_point + (UIntPtr)(*it).size)
		{
			s->insert((*_disasm).EIP - _data_start);
			int len = Disasm(&(*_disasm));
			(*_disasm).EIP = (*_disasm).EIP + (UIntPtr) len;
		}
	}
	done->insert(this);
	for (set <BlockInfo*>::iterator it = _to.begin(); it != _to.end(); ++it)
	{
		if (!done->count(*it))
			(*it)->_getEIPSPasse(s, done);
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
	for (set <BlockInfo*>:: iterator it = newBlock->_to.begin(); it != newBlock->_to.end(); ++it)
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
	assert(_subBlocks.size() == 1);
	assert(_subBlocks[0].size == 0);

	(void) memset (&(*_disasm), 0, sizeof(DISASM));
	(*_disasm).EIP = _subBlocks[0].entry_point;
	//cerr<<"Entry point: "<<(*_disasm).EIP<<endl;
	while ((*_disasm).EIP < _data_end)
	{
		if (_mark[(*_disasm).EIP - _data_start] != NULL)
		{
			BlockInfo* oldBlock = _mark[(*_disasm).EIP - _data_start];
			//cerr<<"went to block"<<(void*)oldBlock<<"at the point"<<(*_disasm).EIP<<endl;
			BlockInfo* newBlock = oldBlock->divideBlock((*_disasm).EIP);
			//cerr<<"this block after division"<<(void*)newBlock<<endl;
			_subBlocks[0].size = (*_disasm).EIP - _subBlocks[0].entry_point;
			newBlock->_from.insert(this);
			_to.insert(newBlock);
			return;
		}
		
		int len = Disasm(&(*_disasm));

		if ((len != UNKNOWN_OPCODE) && (((*_disasm).Instruction.Category & 0xFFFF0000) == SYSTEM_INSTRUCTION))
		{
			//TODO: check if it is really unuseful and not allowed
			len = UNKNOWN_OPCODE;
			
		}

		if (len != UNKNOWN_OPCODE)
		{
			//cerr<<(*_disasm).CompleteInstr<<endl;
			_mark[(*_disasm).EIP - _data_start] = this;
			if ((*_disasm).Instruction.BranchType)
			{
				//cerr<<"Branch Type"<<endl;
				_subBlocks[0].size = (*_disasm).EIP + (UIntPtr) len - _subBlocks[0].entry_point;
				UIntPtr addrToJump = (*_disasm).Instruction.AddrValue;
				UIntPtr curAddr = (*_disasm).EIP;
				if ((*_disasm).Instruction.AddrValue == 0)
					return;
				switch ((*_disasm).Instruction.BranchType)
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
			(*_disasm).EIP = (*_disasm).EIP + (UIntPtr) len;
		}
		else
		{
			//cerr<<"ERROR"<<endl;
			_mark[(*_disasm).EIP - _data_start] = this;
			break;
		}
	}
	_subBlocks[0].size = (*_disasm).EIP - _subBlocks[0].entry_point;
	//cerr<<"Reached the end"<<endl;
}

void BlockInfo::dfs(set <BlockInfo*> *done)
{
	done->insert(this);
	for (set <BlockInfo*>::iterator it = _to.begin(); it != _to.end(); ++it)
	{
		if (!done->count(*it))
			(*it)->dfs(done);
	}
}

void BlockInfo::mergeBlocks()
{
	set <BlockInfo *> done;
	mergeBlocks(&done);
	_normalizer->normalize();
}

void BlockInfo::clearOppositeInstructions(map<string, string>* opposite)
{
	set <BlockInfo*> done;
	clearOppositeInstructions(&done, opposite);
}

void BlockInfo::clearOppositeInstructions(set <BlockInfo* > *done, map<string, string>* opposite)
{
	done->insert(this);
	_clearOppositeInstructions(opposite);
	for(set <BlockInfo*>::iterator it = _to.begin(); it != _to.end(); ++it)
	{
		if (!done->count(*it))
			(*it)->clearOppositeInstructions(done, opposite);
	}
}

vector<BlockInfo::SubBlock>::iterator BlockInfo::cutSubBlock(vector<BlockInfo::SubBlock>::iterator it, 
							     UIntPtr addr, int len)
{
	if (addr != (*it).entry_point)
	{
		if (addr + (UIntPtr) len < (*it).entry_point + (*it).size)
		{
			int newsize = (*it).size - (addr - (*it).entry_point) - len;
			(*it).size = addr - (*it).entry_point;
			++it;
			return _subBlocks.insert(it, SubBlock(addr + (UIntPtr)len, newsize));
		}
		else
		{
			(*it).size = addr - (*it).entry_point;
			return ++it;
		}
	}
	else
	{
		if (addr + (UIntPtr) len < (*it).entry_point + (*it).size)
		{
			(*it).entry_point = addr + (UIntPtr) len;
			return ++it;
		}
		else
		{
			return _subBlocks.erase(it);
		}
	}
}

void BlockInfo::_clearOppositeInstructions(map<string, string>* opposite)
{
	char prev_mnem[16], prev_arg_mnem1[32], prev_arg_mnem2[32], prev_arg_mnem3[32];
	prev_mnem[0]='\0';
	prev_arg_mnem1[0]='\0';
	prev_arg_mnem2[0]='\0';
	prev_arg_mnem3[0]='\0';
	int prev_len = 0;
	UIntPtr prev_addr = 0;
	vector <SubBlock>::iterator prev_subblock = _subBlocks.begin();
	for (vector <SubBlock>::iterator it = _subBlocks.begin(); it != _subBlocks.end(); )
	{
		(void) memset (&(*_disasm), 0, sizeof(DISASM));
		(*_disasm).EIP = (*it).entry_point;
		bool it_changed = false;
		while ((*_disasm).EIP < (*it).entry_point + (*it).size)
		{
			int len = Disasm(&(*_disasm));
			if (opposite->count((*_disasm).Instruction.Mnemonic) && 
				strcmp(prev_mnem, (*opposite)[(*_disasm).Instruction.Mnemonic].c_str()) == 0 && 
				strcmp(prev_arg_mnem1, (*_disasm).Argument1.ArgMnemonic) == 0 &&
				strcmp(prev_arg_mnem2, (*_disasm).Argument2.ArgMnemonic) == 0 &&
				strcmp(prev_arg_mnem3, (*_disasm).Argument3.ArgMnemonic) == 0
			)
			{
				////cerr<<"Cutting from block"<<(void *)this<<endl;
				if (prev_subblock == it)
				{
					it = cutSubBlock(it, prev_addr, prev_len + len);
				}
				else
				{
					it = cutSubBlock(prev_subblock, prev_addr, prev_len);
					it = cutSubBlock(it, (*_disasm).EIP, len);
				}
				prev_subblock = it;
				prev_mnem[0]='\0';
				prev_arg_mnem1[0]='\0';
				prev_arg_mnem2[0]='\0';
				prev_arg_mnem3[0]='\0';
				prev_len = 0;
				prev_addr = 0;
				it_changed = true;
				break;
			}
			else
			{
				prev_len = len;
				prev_addr = (*_disasm).EIP;
				strcpy(prev_mnem, (*_disasm).Instruction.Mnemonic);
				strcpy(prev_arg_mnem1, (*_disasm).Argument1.ArgMnemonic);
				strcpy(prev_arg_mnem2, (*_disasm).Argument2.ArgMnemonic);
				strcpy(prev_arg_mnem3, (*_disasm).Argument3.ArgMnemonic);
				prev_subblock = it;
				(*_disasm).EIP = (*_disasm).EIP + (UIntPtr) len;
			}
		}
		if (!it_changed)
			++it;
	}
}

void BlockInfo::mergeBlocks(set<BlockInfo*> *done)
{
	removeJumpsInside();
	if (_from.size() == 1)
	{
		BlockInfo* parent = (*_from.begin());
		if (parent->_to.size() == 1)
		{
			parent->_to = _to;
			for (set <BlockInfo*>::iterator it = _to.begin(); it != _to.end(); ++it)
			{
				(*it)->_from.erase(this);
				(*it)->_from.insert(parent);
			}
			parent->_subBlocks.push_back(SubBlock(_subBlocks[0].entry_point, _subBlocks[0].size));
			_to.clear();
			_from.clear();
			set <BlockInfo*> children = parent->_to;
			for (set <BlockInfo*>::iterator it = children.begin(); it != children.end(); ++it)
			{
				if (!done->count(*it))
					(*it)->mergeBlocks(done);
			}
			return;
		}
	}
	done->insert(this);
	set <BlockInfo*> children = _to;
	for (set <BlockInfo*>::iterator it = children.begin(); it != children.end(); ++it)
	{
		if (!done->count(*it))
			(*it)->mergeBlocks(done);
	}
	
}

bool BlockInfo::isDirectJx(UIntPtr* addr, int* type)
{
	assert(_subBlocks.size() == 1);
	(void) memset (&(*_disasm), 0, sizeof(DISASM));
	(*_disasm).EIP = _subBlocks[0].entry_point;
	int count = 0;
	bool jump = false;
	while ((*_disasm).EIP < _subBlocks[0].entry_point + (UIntPtr) _subBlocks[0].size)
	{
		int len = Disasm(&(*_disasm));
		if ((*_disasm).Instruction.BranchType && (*_disasm).Instruction.AddrValue != 0 &&
			(*_disasm).Instruction.BranchType != CallType && (*_disasm).Instruction.BranchType != RetType &&
			(*_disasm).Instruction.BranchType != JECXZ && (*_disasm).Instruction.BranchType != JmpType)
		{
			jump = true;
			(*addr) = (*_disasm).Instruction.AddrValue;
			(*type) = (*_disasm).Instruction.BranchType;
		}
		(*_disasm).EIP = (*_disasm).EIP + (UIntPtr)len;
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
	BlockInfo* first = removeJxJnx(&done);
	if (first != NULL)
	{
		_normalizer->changeRoot(first);
	}
	return first;
}


BlockInfo* BlockInfo::removeJxJnx(set<BlockInfo*> *done)
{
	UIntPtr addrJx, addrJnx;
	int jxtype, jnxtype;
	if (isDirectJx(&addrJx, &jxtype))
	{
		bool caseJxJnx = false;
		BlockInfo *blockJnx, *suc_block = NULL;
		for (set <BlockInfo*>::iterator it_jnx = _to.begin(); it_jnx != _to.end(); ++it_jnx)
		{
			if ((*it_jnx)->isDirectJx(&addrJnx,&jnxtype) && (jxtype == -jnxtype) && (addrJx == addrJnx) &&
				(*it_jnx)->_from.size() == 1)
			{
				blockJnx = (*it_jnx);
				caseJxJnx = true;
			}
			else
			{
				suc_block = (*it_jnx);
			}
		}
		if (caseJxJnx && suc_block != NULL)
		{
			for (set <BlockInfo*>::iterator it_par = _from.begin(); it_par != _from.end(); ++it_par)
			{
				(*it_par)->_to.erase(this);
				(*it_par)->_to.insert(suc_block);
				suc_block->_from.insert(*it_par);
			}
			_from.clear();
			if (_first_block)
			{
				suc_block->_first_block = true;
				suc_block->_markResponsable = true;
				_first_block = false;
				_markResponsable = false;
			}
			return suc_block->removeJxJnx(done);	
		}
	}
	done->insert(this);
	set <BlockInfo*> children = _to;
	for (set <BlockInfo*>::iterator it = children.begin(); it != children.end(); ++it)
	{
		if (!done->count(*it))
			(*it)->removeJxJnx(done);
	}
	return this;
}

void BlockInfo::removeJumpsInside()
{
	(void) memset (&(*_disasm), 0, sizeof(DISASM));
	(*_disasm).EIP = _subBlocks[0].entry_point;
	while ((*_disasm).EIP < _subBlocks[0].entry_point + (UIntPtr)_subBlocks[0].size)
	{
		int len = Disasm(&(*_disasm));
		if ((*_disasm).Instruction.BranchType == JmpType && (*_disasm).Instruction.AddrValue != 0)
		{
			_subBlocks[0].size = (*_disasm).EIP - _subBlocks[0].entry_point;
			break;
		}
		(*_disasm).EIP = (*_disasm).EIP + (UIntPtr)len;
	}
}

BlockInfo* BlockInfo::removeJumpsOnly()
{
	set <BlockInfo*> done;
	BlockInfo* first = removeJumpsOnly(&done);
	if (first!=NULL)
		_normalizer->changeRoot(first);
	return (first != NULL) ? first : this;
}


BlockInfo* BlockInfo::removeJumpsOnly(set<BlockInfo*> *done)
{
	assert(_subBlocks.size() == 1);
	//assert(_entry_points.size() == 1);

	if ( _to.size() <= 1)
	/*if (((_from.size() == 1 && (*_from.begin())->_to.size() == 1) || _from.size() == 0) &&
		((_to.size() == 1 && (*_to.begin())->_from.size() == 1) || _to.size() == 0))*/
	{
		(void) memset (&(*_disasm), 0, sizeof(DISASM));
		(*_disasm).EIP = _subBlocks[0].entry_point;
		int count = 0;
		bool jump = false;
		while ((*_disasm).EIP < _subBlocks[0].entry_point + (UIntPtr) _subBlocks[0].size)
		{
			int len = Disasm(&(*_disasm));
			if ((*_disasm).Instruction.BranchType == JmpType && (*_disasm).Instruction.AddrValue != 0)
			{
				jump = true;
			}
			(*_disasm).EIP = (*_disasm).EIP + (UIntPtr)len;
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
					child->_markResponsable = true;
					_first_block = false;
					_markResponsable = false;
				}
				child->_from.erase(this);
				_to.clear();
				return child->removeJumpsOnly(done);
			}
			if (_from.size() != 0 && _to.size() != 0 && !_first_block)
			{
				BlockInfo* child = *(_to.begin());
				child->_from.erase(this);
				for (set <BlockInfo*>::iterator it = _from.begin(); it != _from.end(); ++it)
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
				for (set <BlockInfo*>::iterator it = _from.begin(); it != _from.end(); ++it)
				{
					BlockInfo* parent = (*it);
					parent->_to.erase(this);
				}
				_from.clear();
				return NULL;
			}
		}
	}
	done->insert(this);
	set <BlockInfo*> children = _to;
	for (set<BlockInfo*>::iterator it = children.begin(); it != children.end(); ++it)
	{
		if (!done->count(*it))
			(*it)->removeJumpsOnly(done);
	}
	return this;
}
