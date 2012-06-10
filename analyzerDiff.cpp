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
	int ind_max = CompareUtils::best_match(_data, _shellcodes, THRESHOLD);
	if (ind_max >= 0)
		return _shellcodes[ind_max].name;
	return string();
}
