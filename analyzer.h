#ifndef __ANALYZER_H
#define __ANALYZER_H

#include <vector>
#include <string>
#include <finddecryptor/reader.h>

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
	Reader reader;
	int getdir(string dir, vector<string> &files);
	unsigned char** _shellcodes;
	vector <string> _shellcodeNames;
	int _amountShellcodes;
	int* _shellcodeSizes;
	const unsigned char* _data;
	uint _data_size;
	string _className;
	bool _shellcodes_loaded;
};

ostream & operator<<(ostream &, Analyzer &);
istream & operator>>(istream &, Analyzer &);

#endif //__ANALYZER_H
