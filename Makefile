CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude

CORE_SRC = src/pcap_format.c src/ethernet.c src/ip.c src/tcp.c src/udp.c src/icmp.c
TEST_BINS = bin/test_pcap_format bin/test_ethernet bin/test_ip bin/test_tcp bin/test_udp bin/test_icmp

.PHONY: all test clean

all: bin/pktdump bin/genpcap

bin/pktdump: $(CORE_SRC) src/main.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) src/main.c

bin/genpcap: $(CORE_SRC) src/genpcap.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) src/genpcap.c

test: $(TEST_BINS) bin/pktdump bin/genpcap
	./bin/test_pcap_format
	./bin/test_ethernet
	./bin/test_ip
	./bin/test_tcp
	./bin/test_udp
	./bin/test_icmp
	./tests/test_genpcap_integration.sh

bin/test_pcap_format: $(CORE_SRC) tests/test_pcap_format.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_pcap_format.c

bin/test_ethernet: $(CORE_SRC) tests/test_ethernet.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_ethernet.c

bin/test_ip: $(CORE_SRC) tests/test_ip.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_ip.c

bin/test_tcp: $(CORE_SRC) tests/test_tcp.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_tcp.c

bin/test_udp: $(CORE_SRC) tests/test_udp.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_udp.c

bin/test_icmp: $(CORE_SRC) tests/test_icmp.c
	mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(CORE_SRC) tests/test_icmp.c

clean:
	rm -rf bin
