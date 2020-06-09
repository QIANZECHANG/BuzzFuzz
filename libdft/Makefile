PIN_HOME=/home/binary/libdft/pin-2.13-61206-gcc.4.4.7-linux
DFT_HOME=/home/binary/libdft/libdft-ng_linux-i386/src

CC           = gcc-4.9
CXX          = g++-4.9
CFLAGS      += -m32 -mno-mmx -mno-sse -mno-sse2 -mno-sse3
CXXFLAGS    += -Wall -Wno-unknown-pragmas                         \
                -c -fomit-frame-pointer -std=c++0x -O3            \
               -fno-strict-aliasing -fno-stack-protector          \
               -DBIGARRAY_MULTIPLIER=1 -DUSING_XED                \
               -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX -m32 
CXXFLAGS_SO += -Wl,--hash-style=sysv -Wl,-Bsymbolic -shared -m32  \
               -Wl,-rpath=$(PIN_HOME)/ia32/runtime/cpplibs	  \
               -Wl,--version-script=$(PIN_HOME)/source/include/pin/pintool.ver
LIBS        += -ldft -lpin -lxed -ldwarf -lelf -ldl
H_INCLUDE   += -I$(DFT_HOME)                                      \
               -I$(PIN_HOME)/source/include/pin                   \
               -I$(PIN_HOME)/source/include/pin/gen               \
               -I$(PIN_HOME)/extras/xed2-ia32/include             \
               -I$(PIN_HOME)/extras/components/include
L_INCLUDE   += -L$(DFT_HOME)                                      \
               -L$(PIN_HOME)/extras/xed2-ia32/lib                 \
               -L$(PIN_HOME)/ia-32/runtime/cpplibs                \
               -L$(PIN_HOME)/ia32/lib -L$(PIN_HOME)/ia32/lib-ext

.PHONY: BuzzFuzz.so

BuzzFuzz.so: BuzzFuzz.o
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $(@) $(@:.so=.o) $(LIBS)

BuzzFuzz.o: BuzzFuzz.cpp $(DFT_HOME)/branch_pred.h
	$(CXX) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)

