####### Compiler, tools and options
CXX		= g++ -g -Wall -fPIC -O2 -I.
DEL_FILE		= rm -f

####### Files
OBJECTS_LIB	= \
		analyzer.o \
		analyzerTrace.o \
		analyzerDiff.o \
		analyzerNgram.o \
		analyzerCFG.o \
		block.o \
		normalizer.o \
		changedmemory.o \
		instructionInfo.o \
		compareUtils.o \
		detectSimilar.o \

OBJECTS		= main.o $(OBJECTS_LIB)

TARGET		= analyzer

FLAGS		= --std=c++11
FLAGS_LIB	=

####### Build rules

all: bin lib

bin: $(TARGET)

lib: build/lib/libdetectsimilar.so

clean:
	$(DEL_FILE) $(OBJECTS) *~

####### Compile

analyzer.o: analyzer.cpp analyzer.h
	$(CXX) $(FLAGS) -c analyzer.cpp

analyzerDiff.o: analyzerDiff.cpp analyzerDiff.h analyzer.h compareUtils.h
	$(CXX) $(FLAGS) -c analyzerDiff.cpp

analyzerNgram.o: analyzerNgram.cpp analyzerNgram.h analyzer.h compareUtils.h
	$(CXX) $(FLAGS) -c analyzerNgram.cpp

analyzerCFG.o: analyzerCFG.cpp analyzerCFG.h analyzer.h block.h instructionInfo.h compareUtils.h
	$(CXX) $(FLAGS) -c analyzerCFG.cpp

analyzerTrace.o: analyzerTrace.cpp analyzerTrace.h analyzer.h instructionInfo.h compareUtils.h
	$(CXX) $(FLAGS) -c analyzerTrace.cpp

timer.o: timer.cpp timer.h
	$(CXX) $(FLAGS) -c timer.cpp

compareUtils.o: compareUtils.cpp compareUtils.h
	$(CXX) $(FLAGS) -c compareUtils.cpp

instructionInfo.o: instructionInfo.cpp instructionInfo.h
	$(CXX) $(FLAGS) -c instructionInfo.cpp

detectSimilar.o: detectSimilar.cpp detectSimilar.h analyzer.h
	$(CXX) $(FLAGS) -c detectSimilar.cpp

block.o: block.cpp block.h normalizer.h
	$(CXX) $(FLAGS) -c block.cpp

normalizer.o: normalizer.cpp normalizer.h block.h
	$(CXX) $(FLAGS) -c normalizer.cpp

changedmemory.o: changedmemory.cpp changedmemory.h
	$(CXX) $(FLAGS) -c changedmemory.cpp

main.o: main.cpp detectSimilar.h
	$(CXX) $(FLAGS) -c main.cpp

build/lib/libdetectsimilar.so: $(OBJECTS_LIB)
	mkdir -p build/lib
	$(CXX) $(FLAGS) -shared -o $@ $(OBJECTS_LIB) -lBeaEngine -lemu -lfinddecryptor \
		$(FLAGS_LIB)

$(TARGET): main.o timer.o lib
	$(CXX) $(FLAGS) -o $@ main.o timer.o -lfinddecryptor -ldetectsimilar \
		-L$(CURDIR)/build/lib -Wl,-rpath -Wl,$(CURDIR)/build/lib \
		 $(FLAGS_LIB)


####### Platform-specific targets

local: FLAGS = --std=c++11 -I../include/
local: FLAGS_LIB = -L$(CURDIR)/../lib -Wl,-rpath -Wl,$(CURDIR)/../lib
local: all

debian: FLAGS = --std=c++0x
debian: all

deb: debian distrib/morphdetect.equivs
	equivs-build distrib/morphdetect.equivs
