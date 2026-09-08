# raw-packet-analyzer

A pcap file parser and packet dumper written in plain C, no libpcap. Started as the
C/hardware side track from the study roadmap - a deliberate contrast to pcap-toolkit
(same idea, python + scapy): here every byte gets pulled apart by hand, which is a much
better way to actually understand network byte order, variable-length headers and the
usual C pointer/alignment traps than reading about them.

- `pcap_format.c/h` - reads the libpcap file format directly: the 24 byte global header,
  then a stream of (16 byte packet header, raw bytes) records. handles both byte orders
  (checks the magic number and byte-swaps if the file was written on a different-endian
  machine).
- `ethernet.c/h` - parses the 14 byte ethernet II header (dst/src mac, ethertype). fields
  are pulled out byte by byte instead of casting a struct over the raw buffer, to avoid
  alignment and strict-aliasing issues that come up constantly with that approach in C.
- `ip.c/h` - parses ipv4 headers, including the variable header length case (the ihl
  field can mean anywhere from 20 to 60 bytes once options are present) - this is the
  part that actually breaks naive fixed-size parsing, so it's tested explicitly.
- `main.c` - `pktdump`, a small cli that reads a pcap file and prints a tcpdump-style
  one-line summary per packet.

Still to come: tcp/udp header parsing (ports, tcp flags), and maybe live capture via
raw sockets if this environment allows it (untested so far, might need privileges this
sandbox doesn't have).

## Usage

```
make all
./bin/pktdump tests/fixtures/sample.pcap
```

## Tests

```
make test
```

14 tests across three binaries (pcap format, ethernet, ip), using plain assert() rather
than a test framework - simple, no dependencies, matches the rest of this project's
"nothing fancy, just correct" approach. `tests/fixtures/sample.pcap` is a real pcap
generated with scapy (`tests/fixtures/make_sample_pcap.py`), so the tests are parsing an
actual libpcap file byte for byte, not a hand-rolled approximation.
