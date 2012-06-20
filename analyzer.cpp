#include "analyzer.h"
#include <cstring>
#include <dirent.h>
#include <iostream>
#include <errno.h>

using namespace std;

Analyzer::Analyzer()
{
	_shellcodes_loaded = false;
}

Analyzer::Analyzer(const unsigned char* data, uint size)
{
	_data.link(data, size);
	_shellcodes_loaded = false;
}

Analyzer::~Analyzer()
{
	clear();
}

void Analyzer::load(const unsigned char* data, uint size)
{
	_data.link(data, size);
}

void Analyzer::clear()
{
	_shellcodes.clear();
	_shellcodes_loaded = false;
}

void Analyzer::loadShellcodes(char* dirName)
{
	clear();

	string dir(dirName);
	DIR *dp;
	struct dirent *dirp;
	if ((dp = opendir(dirName)) == NULL)
	{
		cerr << "Error(" << errno << ") opening " << dir << endl;
		return;
	}
	while ((dirp = readdir(dp)) != NULL)
	{
		if (strcmp(dirp->d_name,".") == 0 || strcmp(dirp->d_name,"..") == 0)
			continue;
		string file(dirp->d_name);
		_shellcodes.push_back(Sample(file, dir + file));
	}
	closedir(dp);

	_shellcodes_loaded = true;
}

bool Analyzer::loaded()
{
	return _shellcodes_loaded;
}

ostream & Analyzer::operator<<(ostream &s)
{
	s << _className << endl;
	s << _shellcodes.size() << endl;
	for (auto it = _shellcodes.begin(); it != _shellcodes.end(); ++it)
		s << it->name << " " << it->size << endl;
	for (auto it = _shellcodes.begin(); it != _shellcodes.end(); ++it)
		s.write((const char *) it->data, it->size);
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
	int amountShellcodes;
	s >> amountShellcodes;
	
	for (int i = 0; i < amountShellcodes; i++)
	{
		s >> name;
		int shellcodeSize;
		s >> shellcodeSize;
		_shellcodes.push_back(Sample(name, shellcodeSize));
	}
	s.ignore();
	for (int i = 0; i < amountShellcodes; i++)
	{
		s.read((char *) _shellcodes[i].data, _shellcodes[i].size);
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
