#include "analyzerNgram.h"
#include "compareUtils.h"
#include <iostream>

#define THRESHOLD 0.5

AnalyzerNgram::AnalyzerNgram()
{
	_className = "AnalyzerNgram";
}

AnalyzerNgram::AnalyzerNgram(const unsigned char* data, uint size) 
	: Analyzer(data, size)
{
	_className = "AnalyzerNgram";
}

string AnalyzerNgram::analyze()
{
	int ind_max = CompareUtils::best_match_simple(_data, _data_size, (const unsigned char**) _shellcodes, _shellcodeSizes, _amountShellcodes, THRESHOLD);
	if (ind_max >= 0)
		return _shellcodeNames[ind_max];
	return string();
}
