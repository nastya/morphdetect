#ifndef __ANALYZER_CFG_H
#define __ANALYZER_CFG_H
#include "analyzer.h"
#include <beaengine/BeaEngine.h>
#include <cstring>
#include <stdint.h>
#include <set>
#include "instructionInfo.h"

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
	void buildCFG(int pos, const unsigned char* buf, int buf_size, unsigned char* dest_buf, int* dest_size);
	vector<InstructionInfo> buildInstructions(unsigned char* data, int len);
	void processShellcodes();
	unsigned char* _data_processed;
	unsigned char** _shellcodesProcessed;
	int * _shellcodesProcessedSizes;
	int _data_processed_len;
	vector <InstructionInfo> _instructions;
	vector <InstructionInfo> *_shellcodeInstructions;
	set <int> _eips_passe;
	bool _brut;
};

#endif //__ANALYZER_CFG_H