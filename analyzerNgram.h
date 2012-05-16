#ifndef __ANALYZER_N_GRAM_H
#define __ANALYZER_N_GRAM_H
#include "analyzer.h"
#include <stdint.h>

class AnalyzerNgram : public Analyzer
{
public:
	AnalyzerNgram();
	AnalyzerNgram(const unsigned char* data, uint size);
	string analyze();
};

#endif //__ANALYZER_N_GRAM_H