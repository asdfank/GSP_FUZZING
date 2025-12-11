#!/bin/sh

# check that a single fuzz of a single sample results in the
# same data whether it comes from stdin or a file

fail () {
   echo "input test failed: $@"
   exit 1
}

echo "HAL 2000" > tests/input
cat tests/input | $@ --seed 42 > tests/input-stdin
$@ --seed 42 tests/input > tests/input-file
cmp tests/input-stdin tests/input-file || fail "results differ"
rm tests/input tests/input-file tests/input-stdin


