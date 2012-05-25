#ifndef ___ANALYZER_TRACE_H
#define ___ANALYZER_TRACE_H
#include "analyzer.h"
#include <beaengine/BeaEngine.h>
#include <cstring>
#include <stdint.h>
#include <set>
#include "instructionInfo.h"

class AnalyzerTrace : public Analyzer
{
public:
	AnalyzerTrace(bool brut = true);
	AnalyzerTrace(const unsigned char* data, uint size);
	~AnalyzerTrace();
	string analyze();
	void loadShellcodes(char* dirname);
	ostream & operator<<(ostream &);
	istream & operator>>(istream &);
private:
	void clear();
	string analyze_single(int pos);
	vector<InstructionInfo> buildTrace(int pos, const unsigned char* buf, int buf_size);
	void processShellcodes();
	vector <InstructionInfo> _instructions;
	vector <InstructionInfo> *_shellcodeInstructions;
	set <int> _eips_passe;
	bool _brut;
};


#endif //___ANALYZER_TRACE_H