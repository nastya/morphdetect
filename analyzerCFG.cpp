#include "analyzerCFG.h"
#include "block.h"
#include "compareUtils.h"
#include "wrappers.h"
#include "timer.h"
#include <iostream>
#include <cstring>

#define THRESHOLD 0.5
#define MIN_SHELLCODE_SIZE 30

using namespace std;

AnalyzerCFG::AnalyzerCFG(bool brut): _brut(brut)
{
	_shellcodeInstructions = NULL;
	_className = "AnalyzerCFG";
}

AnalyzerCFG::AnalyzerCFG(const unsigned char* data, uint size)
	: Analyzer(data, size), _brut(true)
{
	_shellcodeInstructions = NULL;
	_className = "AnalyzerCFG";
	
}

void AnalyzerCFG::loadShellcodes(char * dirname)
{
	clear();
	Analyzer::loadShellcodes(dirname);
	processShellcodes();
}

void AnalyzerCFG::clear()
{
	Analyzer::clear();
	if (_shellcodeInstructions != NULL)
		delete [] _shellcodeInstructions;
	_shellcodeInstructions = NULL;
}

void AnalyzerCFG::processShellcodes()
{
	_shellcodeInstructions = new InstructionQueue[_shellcodes.size()];
	for (unsigned int i = 0; i < _shellcodes.size(); i++)
	{
		_cache.clear();
		_shellcodeInstructions[i] = buildCFG(0, _shellcodes[i].data, _shellcodes[i].size);
	}
}

AnalyzerCFG::~AnalyzerCFG()
{
	clear();
}

InstructionQueue AnalyzerCFG::buildCFG(int pos, const unsigned char* buf, int buf_size)
{
	BlockInfo* root = new BlockInfo(&_cache, (UIntPtr) buf,
			(UIntPtr) (buf + buf_size), (UIntPtr)(buf + pos), true);
	root->process();
//	root->generateDot(string("cfg_initial.dot"));
	root->getEIPSPasse(&_eips_passe);
	root = root->removeJumpsOnly();
//	root->generateDot(string("cfg_without_jumps.dot"));
	root->normalize();
	root = root->removeJxJnx();
	root->normalize();
	root = root->removeJxJnx();
	root->normalize();
	root->mergeBlocks();	
	root->normalize();
//	root->generateDot(string("cfg_merged.dot"));
	root->clearOppositeInstructions();
	
	InstructionQueue instructions = root->getInstructions();
	delete root;
	return instructions;
}

string AnalyzerCFG::analyze_single(int pos)
{
	//cerr << "analyze_single launched! POS: " << pos << endl;
	TimerAnalyzer::start(TimeBuild);
	_instructions = buildCFG(pos, _data.data, _data.size);
	TimerAnalyzer::stop(TimeBuild);
	if (_instructions.size() == 0)
		return string();
	int ind_max = _instructions.bestMatch(_shellcodeInstructions, _shellcodes.size(), THRESHOLD);
	if (ind_max >= 0)
		return _shellcodes[ind_max].name;
	return string();

}

string AnalyzerCFG::analyze()
{
	string ans;
	_eips_passe.clear();
	_cache.clear();
	if (_brut)
	{
		for (int pos = 0; pos < (int) _data.size - MIN_SHELLCODE_SIZE; pos++)
		{
			if (!_eips_passe.count(pos))
			{
				ans = analyze_single(pos);
				if (!ans.empty())
					break;
			}
		}
	}
	else
	{
		ans = analyze_single(0);
	}
	_eips_passe.clear();
	return ans;
}

ostream & AnalyzerCFG::operator<<(ostream &s)
{
	/// TODO
	/*
	s << _className << endl;
	s << _amountShellcodes << endl;
	int i = 0;
	for (auto it = _shellcodeNames.begin(); it != _shellcodeNames.end(); ++it, i++)
	{
		s << (*it) << " " << _shellcodesProcessedSizes[i] << " " << _shellcodeInstructions[i].size() << endl;
	}
	for (int i = 0; i < _amountShellcodes; i++)
	{
		s.write((const char *)_shellcodesProcessed[i], _shellcodesProcessedSizes[i]);
	}
	s << endl;
	for (int i = 0; i < _amountShellcodes; i++)
	{
		for (auto it = _shellcodeInstructions[i].begin(); it != _shellcodeInstructions[i].end(); ++it)
		{
			s << ((*it).addr - _shellcodesProcessed[i]) << " " <<(*it).len <<endl;
			//s.write((const char *) _shellcodeInstructions[i], _shellcodeSizes[i]);			
		}
		s << endl;
	}
	*/
	return s;
}
istream & AnalyzerCFG::operator>>(istream &s)
{
	/// TODO
	/*
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
	int* sizes = new int [_amountShellcodes];
	_shellcodesProcessed = new unsigned char * [_amountShellcodes];
	_shellcodesProcessedSizes = new int [_amountShellcodes];
	_shellcodeInstructions = new InstructionQueue[_amountShellcodes];
	for (int i = 0; i < _amountShellcodes; i++)
	{
		s >> name;
		_shellcodeNames.push_back(name);
		s >> _shellcodesProcessedSizes[i] >> sizes[i];
		_shellcodesProcessed[i] = new unsigned char [_shellcodesProcessedSizes[i]];
	}
	s.ignore();
	for (int i = 0; i < _amountShellcodes; i++)
	{
		s.read((char*)_shellcodesProcessed[i], _shellcodesProcessedSizes[i]);
	}
	s.ignore();
	int len;
	int addr;
	for (int i = 0; i < _amountShellcodes; i++)
	{
		for (int j = 0; j < sizes[i]; j++)
		{
			s >> addr >> len;
			_shellcodeInstructions[i].push_back(InstructionInfo(_shellcodesProcessed[i] + addr, len));
		}
	}
	delete [] sizes;
	_shellcodes_loaded = true;
	*/
	return s;
}