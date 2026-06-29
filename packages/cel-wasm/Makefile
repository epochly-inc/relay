# relay-cel-wasm convenience targets. The real pipeline lives in
# conformance/build.sh; this is a thin wrapper for common flows.
#
# Usage (from packages/cel-wasm/):
#   make build         # build the wasm (release) via the reproducible recipe
#   make conformance   # build + oracle + run -> summary.json
#   make parity        # cross-host byte-parity (Python vs Node), diff exit 0
#   make repro         # WS3 cmp-rebuild: two clean builds -> identical sha256
#   make gate          # WS6 release-block: ex-proto 100% AND byte-parity
#   make dist          # WS3 size pass: wasm-opt -Oz -> dist/ vs CF 1MB budget
#   make test          # tier-1 pytest over the wasm
#   make all           # build + conformance + parity + test
#   make ascii-lint    # check source/CLI-output paths are ASCII-only
#   make clean         # remove build + harness artifacts

SHELL := /bin/bash
PKG   := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
CRATE := $(PKG)/crate
CONF  := $(PKG)/conformance
WASM  := $(CRATE)/target/wasm32-unknown-unknown/release/relay_cel_wasm.wasm

REPO_ROOT := $(abspath $(PKG)/../..)
PYTHON    ?= $(if $(wildcard $(REPO_ROOT)/.venv/bin/python),$(REPO_ROOT)/.venv/bin/python,python3)

.PHONY: build conformance parity repro gate dist test all ascii-lint clean

# build goes through build.sh so every artifact the loaders/tests consume is the
# reproducible recipe output (deterministic --remap-path-prefix RUSTFLAGS), not a
# bare `cargo build` whose embedded paths leak the build machine.
build:
	bash $(CONF)/build.sh build

conformance: build
	bash $(CONF)/build.sh oracle
	bash $(CONF)/build.sh run

parity: build
	bash $(CONF)/build.sh parity

repro:
	bash $(CONF)/build.sh repro

gate:
	bash $(CONF)/build.sh gate

dist:
	bash $(CONF)/build.sh dist

test: build
	$(PYTHON) -m pytest $(PKG)/tests -v
	# WS-J edge fuel-timeout node harness (node --test): exercises the TS/edge
	# .mjs loader fuel surface end to end (forwarding, the RELAY-CEL-003 timeout
	# path, and the fail-closed out-of-u64 range guard). Also wired as a pytest
	# plumbing test (relay/tests/conformance/cel/test_wsj_edge_fuel_timeout_node_harness.py)
	# so the CI plumbing gate runs it; this `make test` invocation is the local
	# direct path. CEL_WASM points it at the reproducible-recipe wasm just built.
	CEL_WASM=$(WASM) node --test $(CONF)/harness/wsj_edge_fuel_timeout.test.mjs

all: build conformance parity test

# ASCII-only guard for source + CLI-output paths (CLAUDE.md directive 3).
# Markdown docs may use unicode; the crate src, harness, loaders, and shell
# scripts may not (their output is consumed by CI/auditors/verifiers).
# M3 P3CORPUS additions: also covers the new UDF-via-CEL cross-host driver
# and the TS test file added in WS-E.
ascii-lint:
	@bad=$$(LC_ALL=C grep -rlP '[^\x00-\x7F]' \
		$(CRATE)/src \
		$(CONF)/oracle/main.go \
		$(CONF)/build.sh \
		$(CONF)/harness/udf_via_cel_cross_host.mjs \
		$(PKG)/python/relay_cel_wasm.py \
		$(PKG)/typescript/relay-cel-wasm.mjs \
		2>/dev/null || true); \
	if [ -n "$$bad" ]; then \
		echo "[ascii-lint] FAIL: non-ASCII bytes in source/CLI-output files:"; \
		echo "$$bad"; \
		exit 1; \
	else \
		echo "[ascii-lint] PASS: source + CLI-output paths are ASCII-only"; \
	fi

clean:
	cd $(CRATE) && cargo clean
	rm -f $(CONF)/harness/oracle_records.jsonl \
	      $(CONF)/harness/results.jsonl \
	      $(CONF)/harness/summary.json \
	      $(CONF)/harness/py_dump.txt \
	      $(CONF)/harness/js_dump.txt \
	      $(CONF)/oracle/celoracle
