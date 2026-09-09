#!/bin/sh
# end-to-end check that genpcap's output is actually readable by pktdump -
# the unit tests cover pcap_format/ethernet/ip/tcp/udp in isolation, but
# nothing else exercises the full write-then-parse pipeline through the
# real binaries the way a user would actually run them.
set -e

OUT=$(mktemp /tmp/genpcap_test.XXXXXX.pcap)
trap 'rm -f "$OUT"' EXIT

./bin/genpcap "$OUT" >/dev/null

RESULT=$(./bin/pktdump "$OUT")

echo "$RESULT" | grep -q "203.0.113.5.*:51000 -> 10.0.0.10.*:22.*tcp.*flags=SYN"
echo "$RESULT" | grep -q "10.0.0.5.*:52000 -> 8.8.8.8.*:53.*udp"
echo "$RESULT" | grep -q "^2 packets$"

echo "test_genpcap_integration passed"
