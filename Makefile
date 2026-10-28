CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -pedantic -O2
.PHONY: all test clean
all: ohno-sim

ohno-sim: src/main.cpp src/policy.cpp src/policy.hpp
	$(CXX) $(CXXFLAGS) -Isrc src/main.cpp src/policy.cpp -o $@
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
test: policy-test json-test smbios-test tun-config-test mac-identity-test
	./policy-test
	./json-test
	./smbios-test
	./tun-config-test
	./mac-identity-test
clean:
	rm -f ohno-sim policy-test json-test smbios-test tun-config-test mac-identity-test
