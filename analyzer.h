#ifndef __ANALYZER_H
#define __ANALYZER_H

#include <vector>
#include <string>
#include <istream>
#include <ostream>
#include "sample.h"

using namespace std;

class Analyzer
{
public:
	Analyzer();
	Analyzer(const unsigned char* data, uint size);
	void load(const unsigned char* data, uint size);
	bool loaded();
	virtual ~Analyzer();
	virtual void loadShellcodes(char* dirName);
	virtual string analyze() = 0;
	virtual ostream & operator<<(ostream &);
	virtual istream & operator>>(istream &);

protected:
	virtual void clear();
	vector<Sample> _shellcodes;
	MemoryBlock _data;
	string _className;
	bool _shellcodes_loaded;
};

ostream & operator<<(ostream &, Analyzer &);
istream & operator>>(istream &, Analyzer &);

#endif //__ANALYZER_H
