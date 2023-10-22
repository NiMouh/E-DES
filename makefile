CC = gcc
CFLAGS = -std=c99 -Wall -Wextra
LDFLAGS = -lssl -lcrypto

TARGET = e-des e-des-cpp

OBJS = e-des.o implementation.o

TEST_FILES = *.txt

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

implementation.o: implementation.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) $(OBJS) $(TEST_FILES)

.PHONY: all clean
