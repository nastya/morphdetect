#include "cache.h"
#include <cstring>

#include <iostream>
using namespace std;

DISASM* Cache::getInstruction(UIntPtr addr, int *length)
{
	bool stored = m.count(addr) > 0;
	Disassembler *d = &(m[addr]);

	if (!stored)
	{
		memset(&(d->disas), 0, sizeof(DISASM));
		d->disas.EIP = addr;
		d->len = Disasm(&(d->disas));
	}

	if (length != NULL)
		*length = d->len;
	return &(d->disas);
}

void Cache::clear()
{
	m.clear();
}