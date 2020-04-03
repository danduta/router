PROJECT=router
SOURCES=list.c skel.c table.c
SOURCES-CPP=router.cpp
LIBRARY=nope
INCPATHS=include

LIBPATHS=.
LDFLAGS=
CFLAGS=-c -Wall
CC=gcc
CXX=g++
# Automatic generation of some important lists
OBJECTS=$(SOURCES:.c=.o)
OBJECTS-CPP=$(SOURCES-CPP:.cpp=.o)
INCFLAGS=$(foreach TMP,$(INCPATHS),-I$(TMP))
LIBFLAGS=$(foreach TMP,$(LIBPATHS),-L$(TMP))

# Set up the output file names for the different output types
BINARY=$(PROJECT)

all: $(SOURCES) $(SOURCES-CPP) $(BINARY)

$(BINARY): $(OBJECTS) $(OBJECTS-CPP)
	$(CXX) $(LIBFLAGS) $(OBJECTS-CPP) $(OBJECTS) $(LDFLAGS) -o $@

.c.o:
	$(CXX) $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@

.cpp.o:
	$(CXX) $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@

distclean: clean
	rm -f $(BINARY)

clean:
	rm -f $(OBJECTS)
