CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -O2 -I. -static-libgcc -static-libstdc++
LDFLAGS ?= -static

ifeq ($(OS),Windows_NT)
    LDLIBS += -lws2_32
    EXT = .exe
else
    EXT =
endif

OBJS = hooh/frame.o hooh/headerblock.o hooh/pathutil.o hooh/session.o hooh/fileserve.o hooh/hexdump.o

all: bserve$(EXT) bcurl$(EXT) test_golden$(EXT) test_unit$(EXT)

bserve$(EXT): apps/bserve_main.o $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

bcurl$(EXT): apps/bcurl_main.o $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test_golden$(EXT): tests/test_golden.o hooh/frame.o hooh/headerblock.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test_unit$(EXT): tests/test_unit.o hooh/frame.o hooh/headerblock.o hooh/pathutil.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test: test_golden$(EXT) test_unit$(EXT)
	./test_golden$(EXT)
	./test_unit$(EXT)

clean:
ifeq ($(OS),Windows_NT)
	-cmd /c "del /Q /F hooh\*.o apps\*.o tests\*.o *.exe 2>nul"
else
	rm -f $(OBJS) apps/*.o tests/*.o bserve$(EXT) bcurl$(EXT) test_golden$(EXT)
endif

.PHONY: all test clean
