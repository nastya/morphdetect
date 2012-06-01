#include "analyzer.h"
#include <cstring>
#include <dirent.h>
#include <iostream>
#include <errno.h>

using namespace std;

Analyzer::Analyzer()
{
	_data = NULL;
	_shellcodes = NULL;
	_amountShellcodes = 0;
	_shellcodeSizes = NULL;
	_shellcodes_loaded = false;
}

void Analyzer::load(const unsigned char* data, uint size)
{
	_data = data;
	_data_size = size;
}

Analyzer::Analyzer(const unsigned char* data, uint size): _data(data), _data_size(size)
{
	_shellcodes = NULL;
	_amountShellcodes = 0;
	_shellcodeSizes = NULL;
	_shellcodes_loaded = false;
}

Analyzer::~Analyzer()
{
	clear();
}

void Analyzer::clear()
{
	if (_shellcodes != NULL)
	{
		for (int i = 0; i < _amountShellcodes; i++)
		{
			delete [] _shellcodes[i];
		}
		delete [] _shellcodes;
	}
	if (_shellcodeSizes != NULL)
		delete [] _shellcodeSizes;
	_shellcodes = NULL;
	_shellcodeSizes = NULL;
	_shellcodeNames.clear();
	_shellcodes_loaded = false;
}

void Analyzer::loadShellcodes(char* dirName)
{
	clear();
	getdir(string(dirName), _shellcodeNames);
	_amountShellcodes = _shellcodeNames.size();
	_shellcodes = new unsigned char* [_amountShellcodes];
	_shellcodeSizes = new int [_amountShellcodes];
	int cur = 0;
	for (auto it = _shellcodeNames.begin(); it != _shellcodeNames.end(); ++it, ++cur)
	{
		reader.load(string(dirName)+ (*it));
		_shellcodes[cur] = new unsigned char [reader.size()];
		_shellcodeSizes[cur] = reader.size();
		memcpy(_shellcodes[cur], reader.pointer(), reader.size());
	}
	_shellcodes_loaded = true;
}

int Analyzer::getdir (string dir, vector<string> &files)
{
	DIR *dp;
	struct dirent *dirp;
	if((dp  = opendir(dir.c_str())) == NULL) {
		cout << "Error(" << errno << ") opening " << dir << endl;
		return errno;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (strcmp(dirp->d_name,".")!=0 && strcmp(dirp->d_name,"..")!=0)
				files.push_back(string(dirp->d_name));
	}
	closedir(dp);
	return 0;
}

bool Analyzer::loaded()
{
	return _shellcodes_loaded;
}

ostream & Analyzer::operator<<(ostream &s)
{
	s << _className << endl;
	s << _amountShellcodes << endl;
	int i = 0;
	for (auto it = _shellcodeNames.begin(); it != _shellcodeNames.end(); ++it, i++)
	{
		s << (*it) << " " <<_shellcodeSizes[i] << endl;
	}
	for (int i = 0; i < _amountShellcodes; i++)
	{
		s.write((const char *) _shellcodes[i], _shellcodeSizes[i]);
	}
	return s;
}
istream & Analyzer::operator>>(istream &s)
{
	string name;
	s >> name;
	if (name != _className)
	{
		cerr << "Invalid model" << endl;
		_shellcodes_loaded = false;
		return s;
	}
	clear();
	s >> _amountShellcodes;
	_shellcodes = new unsigned char* [_amountShellcodes];
	_shellcodeSizes = new int [_amountShellcodes];
	
	for (int i = 0; i < _amountShellcodes; i++)
	{
		s >> name;
		_shellcodeNames.push_back(name);
		s >> _shellcodeSizes[i];
		_shellcodes[i] = new unsigned char [_shellcodeSizes[i]];
	}
	s.ignore();
	for (int i = 0; i < _amountShellcodes; i++)
	{
		s.read((char *) _shellcodes[i], _shellcodeSizes[i]);
	}
	_shellcodes_loaded = true;
	return s;
}

ostream & operator<<(ostream &s, Analyzer &x)
{
	return x.operator<<(s);
}
istream & operator>>(istream &s, Analyzer &x)
{
	return x.operator>>(s);
}
