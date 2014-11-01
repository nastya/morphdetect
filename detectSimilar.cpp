#include "detectSimilar.h"
#include <list>
#include "analyzerDiff.h"
#include "analyzerNgram.h"
#include "analyzerCFG.h"
#include "analyzerTrace.h"
#include "changedmemory.h"
#include <fstream>
#include <cstring>
#include "analyzer.h"
#include <finddecryptor/finddecryptor.h>
#include <iostream>
#include <sstream>

using namespace detect_similar;

DetectSimilar::DetectSimilar(AnalyzerType analyzerType, int flags, int minL, int maxL, int finderType,
		int emulatorTypeFD, int emulatorTypeCHM) :
	_emulatorTypeCHM(emulatorTypeCHM), _minLevel(minL), _maxLevel(maxL)
{
	_an = NULL;
	switch (analyzerType)
	{
		case AnalyzerTypeDiff:
			_an = new AnalyzerDiff;
			break;
		case AnalyzerTypeNgram:
			_an = new AnalyzerNgram;
			break;
		case AnalyzerTypeCFG:
			_an = new AnalyzerCFG(flags & AnalyzerFlagBrute);
			break;
		case AnalyzerTypeTrace:
			_an = new AnalyzerTrace(flags & AnalyzerFlagBrute);
			break;
		default:;
	}
	_fd = new FindDecryptor(finderType, emulatorTypeFD);
}

DetectSimilar::~DetectSimilar()
{
	if (_an != NULL)
		delete _an;
	clear();
	delete _fd;
}

void DetectSimilar::clear()
{
	for (size_t cur = 0; cur < _queue.size(); cur++)
		delete[] _queue[cur].first;
	_queue.clear();
	_queue_level.clear();
}

void DetectSimilar::link(const unsigned char* data, int data_size)
{
	_data = (unsigned char *)data;
	_data_size = data_size;
}

void DetectSimilar::loadShellcodes(string dirname)
{
	_an->loadShellcodes((char*)dirname.c_str());
}

bool DetectSimilar::loadModel(string filename)
{
	ifstream in;
	in.open((char*)filename.c_str());
	in >> *_an;
	in.close();
	return (_an->loaded());
}

void DetectSimilar::saveModel(string filename)
{
	ofstream out;
	out.open((char*)filename.c_str());
	out << *_an;
	out.close();
}

void DetectSimilar::unpack()
{
	clear();
	unsigned char* doc = new unsigned char[_data_size];
	memcpy(doc, _data ,_data_size);
	_queue.push_back(block_info(doc, _data_size));
	_queue_level.push_back(0);
	for (size_t cur = 0; cur < _queue.size(); cur++)
	{
		int level = _queue_level[cur];
		if (level >= _maxLevel)
			break;
		//cerr << "Iteration " << cur << endl;
		_fd->link(_queue[cur].first, _queue[cur].second);
		if (_fd->find())
		{
			//cerr << "Decryptor found" << endl;
			list <int> positions = _fd->get_start_list();
			for (auto it = positions.begin(); it != positions.end(); it++)
			{
				//cerr<<"Decryptor on position"<<(*it)<<endl;
				//cout<<"Position: "<<(*it)<<"; size: "<<(*it2)<<endl;
				ChangedMemory mem_class(_queue[cur].first, _queue[cur].second, _emulatorTypeCHM);
				
				int amount_shellcodes = mem_class.compute(*it);
				if (amount_shellcodes == 0)
					continue;
				int* shellcode_size = new int [amount_shellcodes];
				unsigned char** shellcode = new unsigned char* [amount_shellcodes];
				mem_class.getsizes(shellcode_size);
				for (int i = 0; i < amount_shellcodes; i++) {
					shellcode[i] = new unsigned char[shellcode_size[i]];
				}
				mem_class.getmem(shellcode);
				for (int i = 0; i < amount_shellcodes; i++)
				{
					_queue.push_back(block_info(shellcode[i], shellcode_size[i]));
					_queue_level.push_back(level + 1);
				}
				delete[] shellcode;
				delete[] shellcode_size;
			}
		}
		/*
		else
		{
			if (_queue.size() == 1)
				cerr << "Decryptor not found" << endl;
		}
		*/
	}
}

string DetectSimilar::analyze()
{
	if (_data_size == 0)
		return string();
	unpack();
	//cerr << "QUEUE SIZE: " << _queue.size() << endl;
	for (unsigned int i = 0; i < _queue.size();  i++)
	{
		if (_queue_level[i] < _minLevel)
			continue;
		/*ostringstream outstr;
		outstr << "queue_" << i <<".dump";
		ofstream out(outstr.str());
		out.write((const char*)_queue[i].first, _queue[i].second);
		out.close();*/
		
		_an->load(_queue[i].first, _queue[i].second);
		string name = _an->analyze();
		if (!name.empty())
			return name;
	}
	return string();
}
