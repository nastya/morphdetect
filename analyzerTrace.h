#ifndef ___ANALYZER_TRACE_H
#define ___ANALYZER_TRACE_H
#include "analyzer.h"
#include <beaengine/BeaEngine.h>
#include <finddecryptor/emulator.h>
#include <finddecryptor/emulator_libemu.h>
#include <cstring>
#include <stdint.h>
#include <unordered_set>
#include "instructionQueue.h"
#include "traceCache.h"

class AnalyzerTrace : public Analyzer
{
public:
	AnalyzerTrace(bool brut = true);
	AnalyzerTrace(const unsigned char* data, uint size, bool brut = true);
	~AnalyzerTrace();
	string analyze();
	void loadShellcodes(char* dirname);
	ostream & operator<<(ostream &);
	istream & operator>>(istream &);
private:
	void clear();
	string analyze_single(int pos);
	InstructionQueue buildTrace(int pos, const unsigned char* buf, int buf_size);
	void processShellcodes();
	Emulator_LibEmu *_emulator;
	InstructionQueue _instructions;
	InstructionQueue *_shellcodeInstructions;
	unordered_set<int> _eips_passe;
	bool _brut;
	TraceCache _cache;
};


#endif //___ANALYZER_TRACE_H