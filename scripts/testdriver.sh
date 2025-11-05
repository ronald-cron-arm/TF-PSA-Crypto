#!/bin/sh
./scripts/config.py realfull
./build_test_driver.py drivers/builtin drivers libtestdriver1 --verbose
cp tests/testdriver/CMakeLists.txt drivers/libtestdriver1
git checkout -- include/psa/crypto_config.h
