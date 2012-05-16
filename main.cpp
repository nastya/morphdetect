#include "reader.h"
#include "detectSimilar.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>

using namespace std;

int main(int argc, char** argv)
{
	DetectSimilar ds(DetectSimilar::AnalyzerTypeDiff);
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
	Reader reader;
	reader.load(argv[1]);
	ds.link(reader.pointer(), reader.size());

	string ans = ds.analyze();
	if (!ans.empty())
	{
		cout << ans << endl;
	}
	else
	{
		cout << "Not an attack" << endl;
	}
	return 0;
}