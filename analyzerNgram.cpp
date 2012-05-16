#include "analyzerNgram.h"
#include "compareUtils.h"
#include <iostream>

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
	double max_coef = 0.0;
	int ind_max = 0;
	for (int i = 0; i < _amountShellcodes; i++)
	{
		int ans = CompareUtils::compare_simple(_data, _data_size, _shellcodes[i], _shellcodeSizes[i]);
		double coef = ans * 1.0 / _shellcodeSizes[i];
		if (coef > max_coef)
		{
			max_coef = coef;
			ind_max = i;
		}
	}
	if (max_coef > 0.5)
		return _shellcodeNames[ind_max];
	return string();
}
