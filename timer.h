#ifndef TIMER_ANALYZER_H
#define TIMER_ANALYZER_H

#include <cstdlib>
#include <sys/time.h>

enum TimeAnalyzerIds {
	TimeTotal,
	TimeLoadShellcodes,
	TimeLoad,
	TimeNone
};

/**
@brief
Calculate time
*/

class TimerAnalyzer {
public:
	static bool enabled;
	static void start(TimeAnalyzerIds id = TimeTotal);
	static void stop(TimeAnalyzerIds id = TimeTotal);
	static float secs(TimeAnalyzerIds id = TimeTotal);
	static int data[TimeNone];
	static long unsigned int microtime();
};

#endif //TIMER_ANALYZER_H
