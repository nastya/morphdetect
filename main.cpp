#include <finddecryptor/reader.h>
#include "detectSimilar.h"
#include "timer.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <stdlib.h>

using namespace std;

int main(int argc, char** argv)
{
	TimerAnalyzer::start(TimeTotal);
	int type = 1;
	if (argc >= 4)
		type = atoi(argv[3]);
	DetectSimilar ds((DetectSimilar::AnalyzerType)(type));
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
	ds.link(reader.pointer(), reader.size());
	TimerAnalyzer::stop(TimeLoad);

	string ans = ds.analyze();
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
	cerr << "Time spent on loading shellcodes: " << TimerAnalyzer::secs(TimeLoadShellcodes) << endl;
	cerr << "Time spent on loading data to analyze: " << TimerAnalyzer::secs(TimeLoad) << endl;
	return 0;
}
