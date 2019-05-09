#!/bin/bash

set -eux

build_one () {
	local PROG="$1"
	local CFLAGS="-g -fno-stack-protector"
	if [ "$2" = false ]; then
		CFLAGS="$CFLAGS -no-pie -fno-pie"
	fi
	if [ "$3" = false ]; then
		CFLAGS="$CFLAGS -z execstack"
	fi
	gcc $CFLAGS src/$PROG.c -o bin/x86-64/$PROG
	gcc -m32 $CFLAGS src/$PROG.c -o bin/x86/$PROG
	arm-linux-gnueabihf-gcc $CFLAGS src/$PROG.c -o bin/arm/$PROG
	aarch64-linux-gnu-gcc $CFLAGS src/$PROG.c -o bin/arm64/$PROG
	mips-linux-gnu-gcc $CFLAGS src/$PROG.c -o bin/mips/$PROG
	mips64-linux-gnuabi64-gcc $CFLAGS src/$PROG.c -o bin/mips64/$PROG
	powerpc-linux-gnu-gcc $CFLAGS src/$PROG.c -o bin/ppc/$PROG
	powerpc64-linux-gnu-gcc $CFLAGS src/$PROG.c -o bin/ppc64/$PROG
	sparc64-linux-gnu-gcc $CFLAGS src/$PROG.c -o bin/sparc64/$PROG
}

mkdir -p ./bin
mkdir -p ./bin/x86
mkdir -p ./bin/x86-64
mkdir -p ./bin/arm
mkdir -p ./bin/arm64
mkdir -p ./bin/mips
mkdir -p ./bin/mips64
mkdir -p ./bin/ppc
mkdir -p ./bin/ppc64
mkdir -p ./bin/sparc64

build_one "00-hello-pwn" false true
build_one "01-local-overflow" false true
build_one "02-overwrite-ret" false true
build_one "03-one-gadget" false true
build_one "04-shellcode-static" false false
build_one "05-shellcode-dynamic" false false
build_one "06-system-rop" false true
build_one "07-execve-rop" false true
build_one "08-overwrite-global" false true
build_one "99-test" false true
