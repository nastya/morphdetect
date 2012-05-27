#include "analyzerTrace.h"
#include "compareUtils.h"
#include "wrappers.h"
#include <finddecryptor/emulator.h>
#include <finddecryptor/emulator_libemu.h>
//#include <finddecryptor/emulator_qemu.h>
#include <finddecryptor/data.h>
#include <iostream>
#include <cstring>
#include <map>
#define MIN_SHELLCODE_SIZE 30
#define THRESHOLD 0.5 
#define MAX_EMULATE 5000

using namespace std;

AnalyzerTrace::AnalyzerTrace(bool brut): _brut(brut)
{
	_shellcodeInstructions = NULL;
	_className = "AnalyzerTrace";
}

AnalyzerTrace::AnalyzerTrace(const unsigned char* data, uint size)
	: Analyzer(data, size), _brut(true)
{
	_shellcodeInstructions = NULL;
	_className = "AnalyzerTrace";
	
}

void AnalyzerTrace::loadShellcodes(char * dirname)
{
	clear();
	Analyzer::loadShellcodes(dirname);
	processShellcodes();
}

void AnalyzerTrace::clear()
{
	Analyzer::clear();
	if (_shellcodeInstructions != NULL)
	{
		delete [] _shellcodeInstructions;
		_shellcodeInstructions = NULL;
	}
}

void AnalyzerTrace::processShellcodes()
{
	_shellcodeInstructions = new vector <InstructionInfo> [_amountShellcodes];
	for (int i = 0; i < _amountShellcodes; i++)
	{
		_shellcodeInstructions[i] = buildTrace(0, _shellcodes[i], _shellcodeSizes[i]);
	}
}

AnalyzerTrace::~AnalyzerTrace()
{
	clear();
}

vector<InstructionInfo> AnalyzerTrace::buildTrace(int pos, const unsigned char* buf, int buf_size)
{
	vector<InstructionInfo> instructions;

	Reader *r = new Reader(0u);
	r->link(buf, buf_size);
	
	Emulator_LibEmu* emulator;
	emulator = new Emulator_LibEmu;
	emulator -> bind(r);
	emulator -> begin(pos);
	char buff[10];
	DISASM myDisasm;
	
	map <int, int> eip_passe;
	int addr_value = 0, br_type;
	
	for(int i = 0; i < MAX_EMULATE ; i++)
	{
		int num = emulator->get_register(Data::EIP);
		_eips_passe.insert(num);
		if (eip_passe.count(num) != 0)
			eip_passe[num]++;
		else
			eip_passe[num] = 1;
		int len = emulator -> get_command(buff);
			
		if (!len)
		{
			//cerr << "Execution error"<< endl;
			break;
		}
		if (!r->is_valid(num)) {
			break;
		}
		(void) memset (&(myDisasm), 0, sizeof(DISASM));
		myDisasm.EIP = (UIntPtr) buff;
		len = DisasmWrapper(&myDisasm);
		/*
		cerr << i << ": " << "EIP: 0x" << hex << num << " " << myDisasm.CompleteInstr << ", len = " << len <<
				", opcode " << myDisasm.Instruction.Opcode<< endl;
		*/
		if (len == UNKNOWN_OPCODE)
		{
			//cerr << "Unknown opcode encountered" << endl;
			break;
		}
		br_type = myDisasm.Instruction.BranchType;
		if (br_type)
			addr_value = myDisasm.Instruction.AddrValue - myDisasm.EIP;

		if (	!br_type &&
			myDisasm.Instruction.Opcode != 0x00 && // 0x00 = probably junk
			myDisasm.Instruction.Opcode != 0x90) // 0x90 = NOP
			instructions.push_back(InstructionInfo(&myDisasm, len));

		int prev_eip = num;
		if (!emulator -> step())
		{
			//cerr << "Execution error, skipping instruction" << endl;
			emulator->jump(prev_eip + len);
			continue;
		}
		num = emulator->get_register(Data::EIP);
		if (eip_passe.count(num) && eip_passe[num] >= 10 && br_type && br_type != JmpType &&
			br_type != CallType && br_type != RetType)
		{
			if (num != prev_eip + len)
			{
				//cerr << "Changing flow from " << num << " to " << prev_eip + len << endl;
				emulator->jump(prev_eip + len);
			}
			else if (addr_value != 0)
			{
				//cerr << "Changing flow from " << num << " to " << prev_eip + len + addr_value << endl;
				emulator->jump(prev_eip + len + addr_value);
			}
		}
	}
	delete emulator;
	delete r;
	return instructions;
}

string AnalyzerTrace::analyze_single(int pos)
{
	_instructions = buildTrace(pos, _data, _data_size);
	if (_instructions.size() == 0)
		return string();
	double max_coef = 0.0;
	int max_ans = 0;
	int ind_max = 0;
	for (int i = 0; i < _amountShellcodes; i++)
	{
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

string AnalyzerTrace::analyze()
{
	_eips_passe.clear();
	string ans;
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

ostream & AnalyzerTrace::operator<<(ostream &s)
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
istream & AnalyzerTrace::operator>>(istream &s)
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