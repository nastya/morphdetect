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
	TimerAnalyzer::start(TimeMatch);
	float max_coef = 0;
	int max_ans = 0, ind_max = 0;

	unordered_map<mblock, size_t> sample_stat;
	const mbyte *b = _data.data;
	for (size_t i = 0; i <= _data.size - sizeof(mblock); i++, b++)
		sample_stat[*(const mblock *) b]++;

	for (int i = 0; i < _shellcodes.size(); i++)
	{
		int ans = CompareUtils::compare_simple(sample_stat, _shellcodes[i]);
		float coef = ans * 1.0 / _shellcodes[i].size;

		if (coef > THRESHOLD)
		{
			if (coef > max_coef)
			{
				max_coef = coef;
			}
			if (ans > max_ans)
			{
				max_ans = ans;
				ind_max = i;
			}
		}
	}
	TimerAnalyzer::stop(TimeMatch);
	return (max_coef <= THRESHOLD) ? string() : _shellcodes[ind_max].name;
}
