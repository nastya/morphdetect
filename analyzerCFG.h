#ifndef __ANALYZER_CFG_H
#define __ANALYZER_CFG_H
#include "analyzer.h"
#include <beaengine/BeaEngine.h>
#include <cstring>
#include <stdint.h>
#include <set>
#include "instructionQueue.h"
#include "cache.h"

class AnalyzerCFG : public Analyzer
{
public:
	AnalyzerCFG(bool brut = true);
	AnalyzerCFG(const unsigned char* data, uint size);
	~AnalyzerCFG();
	string analyze();
	void loadShellcodes(char* dirname);
	ostream & operator<<(ostream &);
	istream & operator>>(istream &);
private:
	string analyze_single(int pos);
	void clear();
	InstructionQueue buildCFG(int pos, const unsigned char* buf, int buf_size);
	void processShellcodes();
	InstructionQueue _instructions;
	InstructionQueue *_shellcodeInstructions;
	set <int> _eips_passe;
	bool _brut;
	Cache _cache;
};

#endif //__ANALYZER_CFG_H