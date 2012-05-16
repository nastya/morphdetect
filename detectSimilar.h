#ifndef __DETECT_SIMILAR_H
#define __DETECT_SIMILAR_H

#include <string>
#include <vector>

using namespace std;

class Analyzer;
class FindDecryptor;

class DetectSimilar
{
public:
	enum AnalyzerType {
		AnalyzerTypeDiff = 1,
		AnalyzerTypeNgram = 2,
		AnalyzerTypeCFG = 3,
		AnalyzerTypeTrace = 4,
	};
	enum AnalyzerFlag { // 1, 2, 4, 8, 16, 32, 64, 128, etc.
		AnalyzerFlagBrute = 1,
	};

	DetectSimilar(AnalyzerType analyzerType = AnalyzerTypeTrace, int flags = AnalyzerFlagBrute, int minL = 0,
		      int maxL = 1000, int finderType = 0, int emulatorTypeFD = 1, int emulatorTypeCHM = 1);
	~DetectSimilar();
	void link(const unsigned char* data, int data_size);
	void loadShellcodes(string dirname);
	bool loadModel(string filename);
	void saveModel(string filename);
	string analyze();
private:
	typedef pair<unsigned char*, int> block_info;

	void clear();
	void unpack();
	unsigned char* _data;
	int _data_size;
	Analyzer *_an;
	FindDecryptor *_fd;
	int _emulatorTypeCHM; //emulator type for changed memory
	vector<block_info> _queue;
	int _minLevel, _maxLevel;
};
#endif //__DETECT_SIMILAR_H
