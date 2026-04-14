DESTDIR=./lib
SRCDIR=./src
INCLUDE=./include
BINDIR=./bin

# Path to locally built glibc (isolated, does not overwrite system glibc)
# GLIBC_PREFIX=/home/xya/nmo/glibc-2.41-install
# GLIBC_LIB=$(GLIBC_PREFIX)/lib
# GLIBC_INC=$(GLIBC_PREFIX)/include

LIB = $(DESTDIR)/librd.so $(DESTDIR)/librd.a
BIN := $(patsubst %.cc,%,$(wildcard $(BINDIR)/*.cc) $(wildcard lbench/*.cc)) $(patsubst %.c,%,$(wildcard $(BINDIR)/*.c))
TEST := $(filter $(BINDIR)/test_%,$(BIN))
LIB_OBJECTS := $(patsubst %.cc,%.o,$(wildcard $(SRCDIR)/*.cc))
DEPS = $(LIB_OBJECTS:%.o=%.d)

CXX=g++
override CXXFLAGS+= -fopenmp -fPIC -O2 -Wall -std=c++14 -g -I./include  -MMD
CFLAGS = -O2 -Wall -g -MMD -I./include 
LDLIBS=-lpfm -lnuma -ldl

all: $(LIB) $(BIN)

$(TEST) bin/stream: $(DESTDIR)/librd.a

bin/stream: CFLAGS += -fopenmp
bin/setup_waste: LDLIBS=-lnuma

-include $(DEPS)

$(LIB): $(LIB_OBJECTS)
	-mkdir -p $(DESTDIR)
	$(CXX) $(LDFLAGS) $^ -o $@ -shared $(LDLIBS)

clean:
	-rm -rf $(DESTDIR) $(SRCDIR)/*.o $(SRCDIR)/*.d *~ $(BIN) $(BINDIR)/*.d
