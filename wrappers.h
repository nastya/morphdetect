#ifndef __COMMON_H
#define __COMMON_H

#include "timer.h"
#include <beaengine/BeaEngine.h>

inline int DisasmWrapper(DISASM *arg) {
	TimerAnalyzer::start(TimeDisassemble);
	int len = Disasm(arg);
	TimerAnalyzer::stop(TimeDisassemble);	
	return len;
}

#endif // __COMMON_H
