#include "analyzerTrace.h"
#include "emulator.h"
#include "emulator_libemu.h"
#include "emulator_qemu.h"
#include "data.h"
#include "compareUtils.h"

#include <iostream>
#include <cstring>
#include <map>
#define MIN_SHELLCODE_SIZE 30
#define THRESHOLD 0.5 
#define MAX_EMULATE 5000

using namespace std;

AnalyzerTrace::AnalyzerTrace(bool brut): _brut(brut)
{
	_data_processed_len = 0;
	_data_processed = NULL;
	_shellcodesProcessed = NULL;
	_className = "AnalyzerTrace";
}

AnalyzerTrace::AnalyzerTrace(const unsigned char* data, uint size)
	: Analyzer(data, size), _brut(true)
{
	_data_processed_len = 0;
	_data_processed = NULL;
	_shellcodesProcessed = NULL;
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

void AnalyzerTrace::processShellcodes()
{
	_shellcodesProcessed = new unsigned char* [_amountShellcodes];
	_shellcodesProcessedSizes = new int [_amountShellcodes];
	_shellcodeInstructions = new vector <InstructionInfo> [_amountShellcodes];
	for (int i = 0; i < _amountShellcodes; i++)
	{
		_shellcodesProcessed[i] = new unsigned char [_shellcodeSizes[i] * 10];
		buildTrace(0, _shellcodes[i], _shellcodeSizes[i], _shellcodesProcessed[i], &_shellcodesProcessedSizes[i],
			   _shellcodeSizes[i] * 10);
		_shellcodeInstructions[i] = buildInstructions (_shellcodesProcessed[i], _shellcodesProcessedSizes[i]);
	}
}

AnalyzerTrace::~AnalyzerTrace()
{
	clear();
}

void AnalyzerTrace::buildTrace(int pos, const unsigned char* buf, int buf_size, unsigned char* dest_buf,
			       int* dest_size, int max_dest_size)
{
	Reader *r = new Reader(0u);
	r->link(buf, buf_size);
	
	Emulator_LibEmu* emulator;
/*	if (dest_buf == _data_processed)
		emulator = new Emulator_Qemu;
	else*/
		emulator = new Emulator_LibEmu;
	emulator -> bind(r);
	emulator -> begin(pos);
	char buff[10];
	int totallen = 0;
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
		//cout << "EIP: 0x" << hex << num << endl;
		int len = emulator -> get_command(buff);
			
		if (!len)
		{
			cerr << "Execution error"<< endl;
			break;
		}
		//num = emulator->get_register(Data::EIP);
		if (!r->is_valid(num)) {
			if (dest_buf == _data_processed)
				cerr << " Reached end of the memory block, stopping instance." << endl;
			break;
		}
		(void) memset (&(myDisasm), 0, sizeof(DISASM));
		myDisasm.EIP = (UIntPtr) buff;
		len = Disasm(&myDisasm);
		/*cout << i << ": " << "EIP: 0x" << hex << num << " " << myDisasm.CompleteInstr << ", len = " << len << 
				", opcode " << myDisasm.Instruction.Opcode<< endl;
		*/
		if (len == UNKNOWN_OPCODE)
		{
			cerr << "Unknown opcode encountered" << endl;
			break;
		}
		br_type = myDisasm.Instruction.BranchType;
		if (myDisasm.Instruction.BranchType)
			addr_value = myDisasm.Instruction.AddrValue - myDisasm.EIP;
		if ( (dest_buf == _data_processed) && ((myDisasm.Instruction.BranchType != JmpType) || (myDisasm.Instruction.AddrValue == 0)) )
		{
			char buffer[30];
			/*
			cerr << i << ": " << "EIP: 0x" << hex << num << " " << myDisasm.CompleteInstr << ", len = " << len << 
				", opcode " << myDisasm.Instruction.Opcode << endl;
			*/
			emulator->get_memory(buffer, num, 30);
			(void) memset (&(myDisasm), 0, sizeof(DISASM));
			myDisasm.EIP = (UIntPtr) buffer;
			for (int j = 0; j < 0; j++)
			{
				int len = Disasm(&myDisasm);
				cerr << "    " << myDisasm.CompleteInstr << endl;
				myDisasm.EIP = myDisasm.EIP + (UIntPtr) len;
			}
		}
		//cout<<"Len = " << len << endl;
		if (totallen + len >= max_dest_size)
			break;
		memcpy(dest_buf + totallen, (unsigned char*)buff, len);
		totallen += len;
		//cout << "  Command: 0x" << hex << num << ": " << instruction_string(&inst, num) << endl;
		int prev_eip = num;
		if (!emulator -> step())
		{
			cerr << "Execution error, skipping instruction" << endl;
			emulator->jump(prev_eip + len);
			continue;
		}
		num = emulator->get_register(Data::EIP);
		if (eip_passe.count(num) && eip_passe[num] >= 10 && br_type && br_type != JmpType &&
			br_type != CallType && br_type != RetType)
		{
			if (num != prev_eip + len)
			{
				cerr << "Changing flow from " << num << " to " << prev_eip + len << endl; 
				emulator->jump(prev_eip + len);
			}
			else if (addr_value != 0)
			{
				cerr << "Changing flow from " << num << " to " << prev_eip + len + addr_value << endl;
				emulator->jump(prev_eip + len + addr_value);
			}
		}
	}
	delete emulator;
	delete r;
	
	//_data_processed = new unsigned char[_data_size*10];
	*dest_size = totallen;
}

string AnalyzerTrace::analyze_single(int pos)
{
	if (_data_processed != NULL)
		delete [] _data_processed;
	_data_processed = new unsigned char [_data_size * 10];
	buildTrace(pos, _data, _data_size, _data_processed, &_data_processed_len, _data_size * 10);
	//cout << "Dataprocessed len = "<< _data_processed_len << ", max_len = " <<  _data_size * 10 << endl;
	//cout << "Destination buffer size " << _data_processed_len << endl;
	_instructions = buildInstructions(_data_processed, _data_processed_len);
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

vector<InstructionInfo> AnalyzerTrace::buildInstructions(unsigned char* data, int data_size)
{
	DISASM myDisasm;
	(void) memset (&(myDisasm), 0, sizeof(DISASM));
	myDisasm.EIP = (UIntPtr) data;
	vector <InstructionInfo> instructions;
	while (myDisasm.EIP < (UIntPtr)(data + data_size))
	{
		int len = Disasm(&myDisasm);
		
		if (len == UNKNOWN_OPCODE)
		{
			cerr<<"UNKNOWN_OPCODE"<<endl;
			break;
		}
		if (!myDisasm.Instruction.BranchType)
		{
			instructions.push_back(InstructionInfo((unsigned char *)myDisasm.EIP, len));
			if (data == _data_processed)
			{
				//cout << myDisasm.CompleteInstr << endl;
			}
		}
		//out<< (*_disasm).CompleteInstr<< "\\n";
		myDisasm.EIP = myDisasm.EIP + (UIntPtr) len;
	}
	return instructions;
}

ostream & AnalyzerTrace::operator<<(ostream &s)
{
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
	return s;
}
istream & AnalyzerTrace::operator>>(istream &s)
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
	return s;
}