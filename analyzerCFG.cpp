#include "analyzerCFG.h"
#include "block.h"
#include "compareUtils.h"
#include "wrappers.h"
#include <map>
#include <iostream>
#include <cstring>

#define THRESHOLD 0.5
#define MIN_SHELLCODE_SIZE 30

using namespace std;

AnalyzerCFG::AnalyzerCFG(bool brut): _brut(brut)
{
	_data_processed_len = 0;
	_data_processed = NULL;
	_shellcodesProcessed = NULL;
	_className = "AnalyzerCFG";
}

AnalyzerCFG::AnalyzerCFG(const unsigned char* data, uint size)
	: Analyzer(data, size), _brut(true)
{
	_data_processed_len = 0;
	_data_processed = NULL;
	_shellcodesProcessed = NULL;
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
	if (_data_processed != NULL)
		delete [] _data_processed;
	_data_processed = NULL;
	if (_shellcodesProcessed != NULL)
	{
		for (int i = 0; i < _amountShellcodes; i++)
			delete [] _shellcodesProcessed[i];
		delete [] _shellcodesProcessed;
		delete [] _shellcodesProcessedSizes;
		delete [] _shellcodeInstructions;
	}
	_shellcodesProcessed = NULL;
}

void AnalyzerCFG::processShellcodes()
{
	_shellcodesProcessed = new unsigned char* [_amountShellcodes];
	_shellcodesProcessedSizes = new int [_amountShellcodes];
	_shellcodeInstructions = new vector <InstructionInfo> [_amountShellcodes];
	for (int i = 0; i < _amountShellcodes; i++)
	{
		_shellcodesProcessed[i] = new unsigned char [_shellcodeSizes[i] * 10];
		buildCFG(0, _shellcodes[i], _shellcodeSizes[i], _shellcodesProcessed[i], &_shellcodesProcessedSizes[i]);
		_shellcodeInstructions[i] = buildInstructions (_shellcodesProcessed[i], _shellcodesProcessedSizes[i]);
	}
}

AnalyzerCFG::~AnalyzerCFG()
{
	clear();
}

void AnalyzerCFG::buildCFG(int pos, const unsigned char* buf, int buf_size, unsigned char* dest_buf, int* dest_size)
{
	DISASM myDisasm;
	BlockInfo* root = new BlockInfo(&myDisasm, (UIntPtr) buf, 
			(UIntPtr) (buf + buf_size), (UIntPtr)(buf + pos), true);
	root->process();
//	root->generateDot(string("cfg_initial.dot"));
	set <int> eips;
	root->getEIPSPasse(&eips);
	for (set <int>::iterator it = eips.begin(); it != eips.end(); ++it)
		_eips_passe.insert(*it);
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
	
	map<string, string> opposite;
	opposite["add "] = "sub ";
	opposite["sub "] = "add ";
	opposite["xor "] = "xor ";
	opposite["ror "] = "rol ";
	opposite["rol "] = "ror ";
	opposite["xchg "] = "xchg ";
	opposite["btc "] = "btc ";
	
	root->clearOppositeInstructions(&opposite);
	
	*dest_size = root->getProcessed(dest_buf);
	delete root;
}

string AnalyzerCFG::analyze_single(int pos)
{
	//cerr << "analyze_single launched! POS: " << pos << endl;
	if (_data_processed != NULL)
		delete [] _data_processed;
	_data_processed = new unsigned char [_data_size * 10];
	buildCFG(pos, _data, _data_size, _data_processed, &_data_processed_len);
	//cout << "Destination buffer size " << _data_processed_len << endl;
	_instructions = buildInstructions(_data_processed, _data_processed_len);
	if (_instructions.size() == 0) {
		return string();
	}
	double max_coef = 0.0;
	int max_ans = 0;
	int ind_max = 0;
	for (int i = 0; i < _amountShellcodes; i++)
	{
		//int ans = CompareUtils::longest_common_subsequence(_data_processed, _data_processed_len,
		//				     _shellcodesProcessed[i], _shellcodesProcessedSizes[i]);
		int ans = CompareUtils::longest_common_subsequence(_instructions, _shellcodeInstructions[i]);
		//cout<<_shellcodeNames[i]<<": len = "<< _shellcodeInstructions[i].size();
		//cout<<", ans = "<<ans;
		
		double coef = ans * 1.0 / _shellcodeInstructions[i].size();
		//cout<<", coef = "<<coef<<endl;
		if (coef > THRESHOLD)
		{
			max_coef = coef;
			if (ans > max_ans)
			{
				max_ans = ans;
				ind_max = i;
			}
		}
	}
	if (max_coef > THRESHOLD)
		return _shellcodeNames[ind_max];
	return string();
}

string AnalyzerCFG::analyze()
{
	string ans;
	_eips_passe.clear();
	if (_brut)
	{
		for (int pos = 0; pos < _data_size - MIN_SHELLCODE_SIZE; pos++)
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

vector<InstructionInfo> AnalyzerCFG::buildInstructions(unsigned char* data, int data_size)
{
	DISASM myDisasm;
	(void) memset (&(myDisasm), 0, sizeof(DISASM));
	myDisasm.EIP = (UIntPtr) data;
	vector <InstructionInfo> instructions;
	while (myDisasm.EIP < (UIntPtr)(data + data_size))
	{
		int len = DisasmWrapper(&myDisasm);
		/*
		if (data == _data_processed)
		{
			cerr << myDisasm.CompleteInstr << endl;
		}
		*/
		if (len == UNKNOWN_OPCODE)
		{
			//cerr << "UNKNOWN_OPCODE" << endl;
			break;
		}
		if (!myDisasm.Instruction.BranchType)
			instructions.push_back(InstructionInfo(&myDisasm, len));
		//out<< (*_disasm).CompleteInstr<< "\\n";
		myDisasm.EIP = myDisasm.EIP + (UIntPtr) len;
	}
	return instructions;
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
	_shellcodeInstructions = new vector<InstructionInfo> [_amountShellcodes];
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