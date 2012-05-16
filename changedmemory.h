#include "reader.h"
#include "emulator.h"
#include "emulator_libemu.h"
#include "emulator_qemu.h"
#include "data.h"
#include <vector>

typedef pair <unsigned int,unsigned int> IntPair;
using namespace std;

class ChangedMemory
{
public:
	ChangedMemory(char* filename, int emulator_type);
	ChangedMemory(unsigned char* data, int datasize, int emulator_type);
	~ChangedMemory();
	int compute(int entry_point);
	void getsizes(int* shellcode_size);
	void getmem(unsigned char** shellcode);
private:
	void clear();
	bool contains(IntPair new_p, IntPair cur_p);
	bool intersect_left(IntPair new_p, IntPair cur_p);
	bool intersect_right(IntPair new_p, IntPair cur_p);
	bool is_contained_by(IntPair new_p, IntPair cur_p);
	Data::Register convertRegister(int beareg);
	Data::Register convertSegmentRegister(int beareg);
	//bool is_ok(vector<IntPair> intervals);
	//Emulator_LibEmu* emulator;
	Emulator* emulator;
	Reader *reader;
	unsigned char** shellcode;
	int* shellcode_size;
	int amount_shellcodes;	
};
