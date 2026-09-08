CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude

CORE_SRC = src/pcap_format.c src/ethernet.c src/ip.c
TEST_BINS = bin/test_pcap_format bin/test_ethernet bin/test_ip

.PHONY: all test clean

all: bin/pktdump

bin/pktdump: $(CORE_SRC) src/main.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) src/main.c

test: $(TEST_BINS)
	./bin/test_pcap_format
	./bin/test_ethernet
	./bin/test_ip

bin/test_pcap_format: $(CORE_SRC) tests/test_pcap_format.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_pcap_format.c

bin/test_ethernet: $(CORE_SRC) tests/test_ethernet.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_ethernet.c

bin/test_ip: $(CORE_SRC) tests/test_ip.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_ip.c

clean:
	rm -rf bin
