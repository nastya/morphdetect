#include "analyzerDiff.h"
#include "compareUtils.h"
#include <iostream>

using namespace std;

#define THRESHOLD 0.5

AnalyzerDiff::AnalyzerDiff()
{
	_className = "AnalyzerDiff";
}

AnalyzerDiff::AnalyzerDiff(const unsigned char* data, uint size) 
	: Analyzer(data, size)
{
	_className = "AnalyzerDiff";
}

string AnalyzerDiff::analyze()
{
	double max_coef = 0.0;
	int max_ans = 0;
	int ind_max = 0;
	for (int i = 0; i < _amountShellcodes; i++)
	{
		int ans = CompareUtils::compare_diff(_shellcodes[i], _shellcodeSizes[i], _data, _data_size);
		double coef = ans * 1.0 / _shellcodeSizes[i];
		if (coef > THRESHOLD)
		{
			max_coef = coef;
			if (ans > max_ans)
			{
				max_ans = ans;
				ind_max = i;
			}
		}
	}
	if (max_coef > THRESHOLD)
		return _shellcodeNames[ind_max];
	return string();
}
