#include "changedmemory.h"
#include <iostream>
#include <string.h>
#include <beaengine/BeaEngine.h>
#include <vector>
#define EMULATION_CHM_THRESHOLD 3000

namespace detect_similar
{

Data::Register ChangedMemory::convertRegister(int beareg)
{
	switch (beareg)
	{
		case 0x1: return Data::EAX;
		case 0x2: return Data::ECX;
		case 0x4: return Data::EDX;
		case 0x8: return Data::EBX;
		case 0x10: return Data::ESP;
		case 0x20: return Data::EBP;
		case 0x40: return Data::ESI;
		case 0x80: return Data::EDI;
		default: return Data::NOREG;
	}
}

Data::Register ChangedMemory::convertSegmentRegister(int beareg)
{
	switch (beareg)
	{
		case 0x1: return Data::ES;
		case 0x2: return Data::DS;
		case 0x3: return Data::FS;
		case 0x4: return Data::GS;
		case 0x5: return Data::CS;
		case 0x6: return Data::SS;
		default: return Data::NOREG;
	}
}
bool ChangedMemory::contains(IntPair new_p, IntPair cur_p)
{
	return (new_p.first<=cur_p.first && new_p.second >=cur_p.second);
}

bool ChangedMemory::is_contained_by(IntPair new_p, IntPair cur_p)
{
	return (new_p.first>=cur_p.first && new_p.second <=cur_p.second);
}

bool ChangedMemory::intersect_left(IntPair new_p, IntPair cur_p)
{
	return (new_p.first<=cur_p.first-1 && new_p.second>=cur_p.first-1);
}

bool ChangedMemory::intersect_right(IntPair new_p, IntPair cur_p)
{
	return (new_p.second>=cur_p.second+1 && new_p.first<=cur_p.second+1);
}
ChangedMemory::ChangedMemory(char* filename, int emulator_type)
{
	reader=new Reader;
	reader->load(filename);
	switch (emulator_type)
	{
		case 1: emulator = new Emulator_LibEmu; 
			break;
		/*
		case 2: emulator = new Emulator_Qemu;
			break;
		*/
		default:;
	}
	emulator -> bind(reader);
	shellcode = NULL;
	shellcode_size = NULL;
	amount_shellcodes = 0;
}

ChangedMemory::ChangedMemory(unsigned char* data, int datasize, int emulator_type)
{
	reader=new Reader;
	reader->link(data, datasize);
	switch (emulator_type)
	{
		case 1: emulator = new Emulator_LibEmu; 
			break;
		/*
		case 2: emulator = new Emulator_Qemu;
			break;
		*/
		default:;
	}
	emulator -> bind(reader);
	shellcode = NULL;
	shellcode_size = NULL;
	amount_shellcodes = 0;
}


ChangedMemory::~ChangedMemory()
{
	delete reader;
	delete emulator;
	clear();
}

void ChangedMemory::getsizes(int* size)
{
	for (int i = 0; i < amount_shellcodes; i++)
	{
		size[i]=shellcode_size[i];
	}
}

void ChangedMemory::getmem(unsigned char** bytes)
{
	for (int i = 0; i < amount_shellcodes; i++)
	{
		for (int j = 0; j < shellcode_size[i]; j++)
		{
			bytes[i][j] = shellcode[i][j];
		}
	}
}

void ChangedMemory::clear()
{
	for (int i = 0; i < amount_shellcodes; i++)
	{
		delete [] shellcode[i];
	}
	if (shellcode != NULL)
		delete [] shellcode;
	if (shellcode_size != NULL)
		delete [] shellcode_size;
	shellcode = NULL;
	shellcode_size = NULL;
	amount_shellcodes = 0;
}

/*bool ChangedMemory::is_ok(vector<IntPair> intervals)
{
	for (unsigned int i = 0; i < intervals.size(); i++)
	{
		if (intervals[i].first > intervals[i].second)
			return false;
	}
	for (unsigned int i = 0; i < intervals.size() - 1; i++)
	{
		if (intervals[i+1].first <= intervals[i].second)
			return false;
	}
	return true;
}*/

int ChangedMemory::compute(int entry_point)
{
	clear();
	emulator -> begin(entry_point);
	char buf[10];
	DISASM MyDisasm;
	(void) memset (&MyDisasm, 0, sizeof(DISASM));
	MyDisasm.EIP = (UIntPtr) buf;

	unsigned int memory_changing;
	unsigned int *max_addr = NULL, *min_addr = NULL;
	IntPair p;
	
	vector<IntPair> intervals, intervals_before;
	for (int i = 0; i < EMULATION_CHM_THRESHOLD ; i++)
	{
		if (!emulator -> get_command(buf))
		{
			//cerr << "Execution error"<< endl;
			break;
		}
		int num = emulator->get_register(Data::EIP);
		if (!reader->is_valid(num)) {
			//cout << " Reached end of the memory block, stopping instance." << endl;
			break;
		}
		int len = Disasm(&MyDisasm);
		if (len == UNKNOWN_OPCODE)
		{
			break;
		}
		//printf("%s\n", MyDisasm.CompleteInstr);
		int num1 = 0, num2 = 0;
		if (MyDisasm.Argument1.AccessMode == WRITE && MyDisasm.Argument1.ArgType == MEMORY_TYPE &&
			MyDisasm.Argument1.ArgSize != 0)
		{
			if (convertRegister(MyDisasm.Argument1.Memory.BaseRegister)!=Data::NOREG)
				num1=emulator->get_register(convertRegister(MyDisasm.Argument1.Memory.BaseRegister));
			if (convertRegister(MyDisasm.Argument1.Memory.IndexRegister)!=Data::NOREG)
				num2=emulator->get_register(convertRegister(MyDisasm.Argument1.Memory.IndexRegister));
			memory_changing = num1+MyDisasm.Argument1.Memory.Scale*num2+MyDisasm.Argument1.Memory.Displacement;
			if (min_addr == NULL)
			{
				min_addr = new unsigned int;
				*min_addr = memory_changing;
			}
			if (max_addr == NULL)
			{
				max_addr = new unsigned int;
				*max_addr = memory_changing+ MyDisasm.Argument1.ArgSize -1;
			}
			if (memory_changing < *min_addr)
				*min_addr = memory_changing;
			if (memory_changing+ MyDisasm.Argument1.ArgSize -1 > *max_addr)
				*max_addr = memory_changing+ MyDisasm.Argument1.ArgSize -1;
			
			p.first = memory_changing;
			p.second = memory_changing + MyDisasm.Argument1.ArgSize -1; 
			
			unsigned int ind = 0;
			bool inserted = false;
			intervals_before = intervals;
			for (ind = 0; ind < intervals.size(); ind++)
			{
				if (is_contained_by(p,intervals[ind]))
				{
					inserted = true;
				}
				if (contains(p,intervals[ind]))
				{
					intervals[ind] = p;
					inserted = true;
				}
				if (intersect_left(p, intervals[ind]))
				{
					intervals[ind].first = p.first;
					inserted = true;
				}
				if (intersect_right(p, intervals[ind]))
				{
					intervals[ind].second = p.second;
					inserted = true;
				} 
			}
			if (inserted)
			{
				for (ind = 0; ind < intervals.size()-1; )
				{
					if (intervals[ind].second>=intervals[ind+1].first)
					{
						intervals[ind].second = intervals[ind+1].second;
						intervals.erase(intervals.begin() + ind+1);
					}
					else
						ind++;
				}
			}
			else
			{
				for (ind = 0; ind <intervals.size() && intervals[ind].first < p.first; ind++);
				intervals.insert( intervals.begin()+ind, p);
			}
			
		}
		emulator -> step();
		/*if (!emulator -> step())
		{
			cerr << "Execution error, skipping instruction" << endl;
			emulator->jump(num + len);
		}*/
	}
	
	shellcode = new unsigned char* [intervals.size()];
	shellcode_size = new int [intervals.size()];
	for (unsigned int i=0; i < intervals.size(); i++)
		shellcode[i] = NULL;
	amount_shellcodes = 0;
	for (unsigned int i=0; i<intervals.size(); i++)
	{
		if (intervals[i].second < intervals[i].first + 20)
			continue;
		if (intervals[i].first - reader->entrance() >= reader->size())
			continue;
		if (intervals[i].second - reader->entrance() >= reader->size())
			intervals[i].second = reader->size() - 1 + reader->entrance();
		shellcode_size[amount_shellcodes] = intervals[i].second - intervals[i].first + 1;
		shellcode[amount_shellcodes] = new unsigned char[shellcode_size[amount_shellcodes]];
		emulator->get_memory((char *) shellcode[amount_shellcodes], intervals[i].first, shellcode_size[amount_shellcodes]);
		amount_shellcodes++;
	}
	delete min_addr;
	delete max_addr;
	return amount_shellcodes;
	
}

} //namespace detect_similar
