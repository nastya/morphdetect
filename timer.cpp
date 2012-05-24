#include "timer.h"

bool TimerAnalyzer::enabled = true;
int TimerAnalyzer::data[TimeNone] = {0};

long unsigned int TimerAnalyzer::microtime()
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	return (long unsigned int) (1e6*tv.tv_sec + tv.tv_usec);
}
void TimerAnalyzer::start(TimeAnalyzerIds id)
{
	if (!enabled) {
		return;
	}
	data[id] -= microtime();
}
void TimerAnalyzer::stop(TimeAnalyzerIds id)
{
	if (!enabled) {
		return;
	}
	data[id] += microtime();
}
float TimerAnalyzer::secs(TimeAnalyzerIds id)
{
	return data[id] * 1e-6;
}
