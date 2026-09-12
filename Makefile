# Plain make, no cmake: the engine has no external dependencies and should
# build anywhere a C11 compiler exists.

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion
CPPFLAGS = -Iinclude
LDFLAGS ?=

BIN     := build/ngfw-classify
SRCS    := src/engine/main.c src/engine/decode.c src/engine/tls.c \
           src/engine/flow.c src/engine/pcap.c \
           src/match/domain_trie.c src/match/lpm.c src/match/payload.c src/sigdb/sigdb_load.c
OBJS    := $(SRCS:%.c=build/%.o)

TEST_BIN  := build/test_trie
TEST_SRCS := tests/test_trie.c src/match/domain_trie.c
TEST_OBJS := $(TEST_SRCS:%.c=build/%.o)

TEST_LPM_BIN  := build/test_lpm
TEST_LPM_SRCS := tests/test_lpm.c src/match/lpm.c
TEST_LPM_OBJS := $(TEST_LPM_SRCS:%.c=build/%.o)

TEST_PAY_BIN  := build/test_payload
TEST_PAY_SRCS := tests/test_payload.c src/match/payload.c
TEST_PAY_OBJS := $(TEST_PAY_SRCS:%.c=build/%.o)

.PHONY: all clean test sigdb pcap check run audit page

all: $(BIN)

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(TEST_BIN): $(TEST_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(TEST_LPM_BIN): $(TEST_LPM_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(TEST_PAY_BIN): $(TEST_PAY_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

test: $(TEST_BIN) $(TEST_LPM_BIN) $(TEST_PAY_BIN)
	./$(TEST_BIN)
	./$(TEST_LPM_BIN)
	./$(TEST_PAY_BIN)

# Compile the signature database from the vendored corpora.
sigdb:
	./.venv/bin/python tools/sigc.py --out build/ngfw.sigdb --emit-json build/inventory.json
	./.venv/bin/python tools/sigc.py --out build/permissive.sigdb --max-license permissive

# Synthesized ClientHellos: validates the matching path, not signature accuracy.
pcap: sigdb
	./.venv/bin/python tools/mkpcap.py --out tests/pcap/tls_sni.pcap
	./.venv/bin/python tools/corpus_pcap.py --db build/ngfw.sigdb --out build/all_hosts.pcap
	./.venv/bin/python tools/mkpcap.py --out build/fusion.pcap --hosts-file tests/fusion_hosts.txt
	./.venv/bin/python tools/mkproto_pcap.py --out build/proto.pcap

page: sigdb
	./.venv/bin/python tools/build_page.py

audit: sigdb
	./.venv/bin/python tools/dup_audit.py --db build/ngfw.sigdb

check: all test sigdb pcap
	./tests/run_e2e.sh
	@./.venv/bin/python tools/dup_audit.py --db build/ngfw.sigdb | tail -3

run: all sigdb pcap
	./$(BIN) build/ngfw.sigdb tests/pcap/tls_sni.pcap

clean:
	rm -rf build
