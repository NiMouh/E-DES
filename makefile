CC = gcc
LDFLAGS = -lcrypto
TARGETS = e-des speed
OBJECTS = implementation.o

all: $(TARGETS)

e-des: e-des.c $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

speed: speed.c $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c $<

clean:
	rm -f $(TARGETS) $(OBJECTS)

.PHONY: all clean