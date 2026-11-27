CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -pedantic -O2
GO ?= go
VERSION := $(shell cat VERSION)

.PHONY: all teacher pkg test test-cpp test-go test-js test-parity check-no-python clean

all: ohno-sim ohno-teacher ohno-pkg

ohno-sim: src/main.cpp src/policy.cpp src/policy.hpp
	$(CXX) $(CXXFLAGS) -Isrc src/main.cpp src/policy.cpp -o $@

ohno-teacher:
	$(GO) build -trimpath -ldflags="-s -w -X main.Version=v$(VERSION)" -o $@ ./cmd/ohno-teacher

ohno-pkg:
	$(GO) build -trimpath -ldflags="-s -w" -o $@ ./cmd/ohno-pkg

policy-test: tests/policy_test.cpp src/policy.cpp src/policy.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/policy_test.cpp src/policy.cpp -o $@
json-test: tests/json_test.cpp src/json.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/json_test.cpp -o $@
smbios-test: tests/smbios_test.cpp src/smbios.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/smbios_test.cpp -o $@
tun-config-test: tests/tun_config_test.cpp src/tun_config.hpp src/json.hpp src/policy.cpp src/policy.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/tun_config_test.cpp src/policy.cpp -o $@
mac-identity-test: tests/mac_identity_test.cpp src/mac_identity.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/mac_identity_test.cpp -o $@
setup-bundle-test: tests/setup_bundle_test.cpp windows/setup_bundle.hpp
	$(CXX) $(CXXFLAGS) tests/setup_bundle_test.cpp -o $@
client-policy-test: tests/client_policy_test.cpp src/client_policy.hpp src/json.hpp src/policy.cpp src/policy.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/client_policy_test.cpp src/policy.cpp -o $@
approval-queue-test: tests/approval_queue_test.cpp src/approval_queue.hpp src/json.hpp src/policy.cpp src/policy.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/approval_queue_test.cpp src/policy.cpp -o $@
update-manifest-test: tests/update_manifest_test.cpp src/update_manifest.hpp src/json.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/update_manifest_test.cpp -o $@
update-transaction-test: tests/update_transaction_test.cpp src/update_transaction.hpp src/update_manifest.hpp src/json.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/update_transaction_test.cpp -o $@
update-package-test: tests/update_package_test.cpp src/update_package.hpp src/update_manifest.hpp src/json.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/update_package_test.cpp -o $@
update-health-test: tests/update_health_test.cpp src/update_health.hpp src/agent_health.hpp src/update_transaction.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/update_health_test.cpp -o $@

check-no-python:
	@if [ -n "$$(find . -name '*.py' -not -path './.git/*')" ]; then echo "Python files are forbidden in this repository" >&2; exit 1; fi

test-cpp: policy-test json-test smbios-test tun-config-test mac-identity-test setup-bundle-test client-policy-test approval-queue-test update-manifest-test update-transaction-test update-package-test update-health-test
	./policy-test
	./json-test
	./smbios-test
	./tun-config-test
	./mac-identity-test
	./setup-bundle-test
	./client-policy-test
	./approval-queue-test
	./update-manifest-test
	./update-transaction-test
	./update-package-test
	./update-health-test

test-go:
	$(GO) test -race -v ./teacher/...

test-parity: update-package-test
	OHNO_UPDATE_PACKAGE_TEST="$(CURDIR)/update-package-test" $(GO) test -v ./tests/integration

test-js:
	node tests/update_ui_test.js

test: check-no-python test-cpp test-go test-parity test-js

clean:
	rm -f ohno-sim ohno-teacher ohno-pkg policy-test json-test smbios-test tun-config-test mac-identity-test setup-bundle-test client-policy-test approval-queue-test update-manifest-test update-transaction-test update-package-test update-health-test
