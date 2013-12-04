#!/bin/sh
ios-clang fuzzer.c -framework IOSurface -framework CoreFoundation -framework IOKit
scp -P 2222 a.out root@localhost:~/
