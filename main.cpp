#include <finddecryptor/reader.h>
#include "detectSimilar.h"
#include "timer.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <algorithm>

#define BLOCK_SIZE 40000u
#define OVERLAP 20000u
//#define BLOCK_SIZE 1500u
//#define OVERLAP 100u

using namespace std;

int main(int argc, char** argv)
{
	TimerAnalyzer::start(TimeTotal);
	uint bl_size = BLOCK_SIZE;
	int type = 1;
	if (argc >= 4)
		type = atoi(argv[3]);
	if (argc >= 6)
		bl_size = atoi(argv[5]);
	uint overlap = min(bl_size / 2, OVERLAP);

	DetectSimilar ds((DetectSimilar::AnalyzerType)(type), DetectSimilar::AnalyzerFlagBrute, (argc >= 5) ? atoi(argv[4]) : 0);
	TimerAnalyzer::start(TimeLoadShellcodes);
	if (argv[2][strlen(argv[2])-1] == '/')
	{
		ds.loadShellcodes(argv[2]);
	} 
	else 
	{
		if (!ds.loadModel(argv[2]))
		{
			cerr << "Error: could not load model." << endl;
			return 0;
		}
	}
	TimerAnalyzer::stop(TimeLoadShellcodes);
	TimerAnalyzer::start(TimeLoad);
	Reader reader;
	reader.load(argv[1]);
	TimerAnalyzer::stop(TimeLoad);

	/*
	ds.link(reader.pointer(), reader.size());
	string ans = ds.analyze();
	*/
	string ans;
	for (int data_start = 0, i = 0; data_start < reader.size(); data_start += bl_size - overlap, i++)
	{
		if (i > 0)
			cerr << 100 * (float) data_start / reader.size() << "% processed" << endl;

		ds.link(reader.pointer() + data_start, min(reader.size() - data_start, bl_size));
		string my_ans = ds.analyze();
		if (!my_ans.empty()) {
			ans = my_ans;
			break;
		}
	}

	if (!ans.empty())
	{
		cout << ans << endl;
	}
	else
	{
		cout << "Not an attack" << endl;
	}

	TimerAnalyzer::stop(TimeTotal);
	cerr << "Total time: " << TimerAnalyzer::secs(TimeTotal) << endl;
#ifdef TIMER_DETAILED
	cerr << "Time spent on loading shellcodes: " << TimerAnalyzer::secs(TimeLoadShellcodes) << endl;
	cerr << "Time spent on loading data to analyze: " << TimerAnalyzer::secs(TimeLoad) << endl;
	cerr << "Time spend on building data: " << TimerAnalyzer::secs(TimeBuild) << endl;
	cerr << "Time spend on disassembling: " << TimerAnalyzer::secs(TimeDisassemble) << endl;
	cerr << "Time spend on matching: " << TimerAnalyzer::secs(TimeMatch) << endl;
	cerr << "Time spend on lcs: " << TimerAnalyzer::secs(TimeLCS) << endl;
#endif
	return 0;
}
