#!/bin/sh
~/other_projects/arc4-toolchain-20100305-x86/usr/local/arc/arc-elf32/bin/as test.s -o test.o
~/other_projects/arc4-toolchain-20100305-x86/usr/local/arc/arc-elf32/bin/ld test.o -o test

