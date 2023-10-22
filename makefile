GXX = g++
LDFLAGS = -lcrypto
TARGETS = e-des e-des-cpp
OBJECTS = implementation.o

all: $(TARGETS)

e-des: e-des.c $(OBJECTS)
	$(GXX) -o $@ $^ $(LDFLAGS)

e-des-cpp: e-des-cpp.cpp $(OBJECTS)
	$(GXX) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(GXX) -c $<

clean:
	rm -f $(TARGETS) $(OBJECTS)

.PHONY: all clean