CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -pedantic -O2
.PHONY: all test clean
all: ohno-sim

ohno-sim: src/main.cpp src/policy.cpp src/policy.hpp
	$(CXX) $(CXXFLAGS) -Isrc src/main.cpp src/policy.cpp -o $@
policy-test: tests/policy_test.cpp src/policy.cpp src/policy.hpp
	$(CXX) $(CXXFLAGS) -Isrc tests/policy_test.cpp src/policy.cpp -o $@
test: policy-test
	./policy-test
clean:
	rm -f ohno-sim policy-test
