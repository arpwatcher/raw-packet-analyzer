CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude

CORE_SRC = src/pcap_format.c src/ethernet.c
TEST_BINS = bin/test_pcap_format bin/test_ethernet

.PHONY: test clean

test: $(TEST_BINS)
	./bin/test_pcap_format
	./bin/test_ethernet

bin/test_pcap_format: $(CORE_SRC) tests/test_pcap_format.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_pcap_format.c

bin/test_ethernet: $(CORE_SRC) tests/test_ethernet.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_ethernet.c

clean:
	rm -rf bin
