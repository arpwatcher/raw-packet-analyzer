CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude

SRC = src/pcap_format.c

.PHONY: test clean

test: bin/test_pcap_format
	./bin/test_pcap_format

bin/test_pcap_format: $(SRC) tests/test_pcap_format.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(SRC) tests/test_pcap_format.c

clean:
	rm -rf bin
