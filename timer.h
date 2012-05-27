#ifndef TIMER_ANALYZER_H
#define TIMER_ANALYZER_H

#include <cstdlib>
#include <sys/time.h>

//#define TIMER_DETAILED

enum TimeAnalyzerIds {
	TimeTotal,
	TimeProcess,
	TimeLoadShellcodes,
	TimeDisassemble,
	TimeBuild,
	TimeMatch,
	TimeLCS,
	TimeLoad,
	TimeNone
};

/**
@brief
Calculate time
*/

class TimerAnalyzer {
public:
	static inline void start(TimeAnalyzerIds id = TimeTotal)
	{
#ifndef TIMER_DETAILED
		if (id != TimeTotal && id != TimeProcess) return;
#endif
		if (!enabled) return;
		data[id] -= microtime();
	}
	static inline void stop(TimeAnalyzerIds id = TimeTotal)
	{
#ifndef TIMER_DETAILED
		if (id != TimeTotal && id != TimeProcess) return;
#endif
		if (!enabled) return;
		data[id] += microtime();
	}
	static inline float secs(TimeAnalyzerIds id = TimeTotal)
	{
		return data[id] * 1e-6;
	}
	static inline long unsigned int microtime()
	{
		struct timeval tv;
		gettimeofday(&tv,NULL);
		return (long unsigned int) (1e6*tv.tv_sec + tv.tv_usec);
	}

	static bool enabled;
	static int data[TimeNone];
};

#endif //TIMER_ANALYZER_H
