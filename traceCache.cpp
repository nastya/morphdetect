#include "traceCache.h"
#include <cstring>
#include "wrappers.h"

DISASM* TraceCache::getInstruction(int eip, void *addr, int *length)
{
	bool stored = m.count(eip) > 0;
	TraceDisassembler *d = &(m[eip]);

	if (stored && (memcmp(d->buf, addr, (d->len > 0) ? d->len : 10) != 0)) {
		extra.push(DISASM());
		DISASM *last = &(extra.back());
		memset(last, 0, sizeof(DISASM));
		last->EIP = (UIntPtr) addr;
		int len = DisasmWrapper(last);
		if (length != NULL)
			*length = len;
		return last;
	}

	if (!stored)
	{
		memset(&(d->disas), 0, sizeof(DISASM));
		d->disas.EIP = (UIntPtr) addr;
		d->len = DisasmWrapper(&(d->disas));
		memcpy(d->buf, addr, (d->len > 0) ? d->len : 10);
	}

	if (length != NULL)
		*length = d->len;
	return &(d->disas);
}

void TraceCache::clear()
{
	m.clear();
	extra = queue<DISASM>();
}