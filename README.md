Easy Linux PWN
==============

This is a set of Linux binary exploitation tasks for beginners. Right now they are only oriented on stack buffer-overflows.

I've created these tasks to learn how to do simple binary exploitation on different architectures.
For educational purposes while solving the tasks you have to follow a set of rules listed below.
The tasks are made deliberately small and some of the rules are deliberately unrealistic.
Contrary to most CTF challenges, in these tasks the solution is given to you, you just have to implement it.


## Rules

1. All tasks must be solved using the suggested approach even if there are other easier ways.

2. All tasks must be solved with specific protections assumed to be enabled or disabled (even if the architecture, the toolchain or the environment doesn't support it).

3. All tasks assume a dynamically linked libc with a known binary.

4. All ROP chains must be built manually.


## Tasks

### Suggested approaches

1. [01-local-overflow](src/01-local-overflow.c):
overflow `buffer` and overwrite `x` with the desired value.

2. [02-overwrite-ret](src/02-overwrite-ret.c):
overwrite any of the return addresses on stack with the address of `not_called()`.

3. [03-one-gadget](src/03-one-gadget.c):
jump to a [one\_gadget](https://github.com/david942j/one_gadget) address.
Make sure to satisfy the required constaints if there are any.
For some of the architectures this might require using a ROP chain, which technically makes "one\_gadget" no longer "one".

4. [04-shellcode-static](src/04-shellcode-static.c):
allocate a shellcode on the stack that launches `/bin/sh` and jump to it.
Assume that the shellcode address on the stack is known.
No need to deal with [cache coherency](https://blog.senr.io/blog/why-is-my-perfectly-good-shellcode-not-working-cache-coherency-on-mips-and-arm) on ARM, MIPS and PowerPC.

5. [05-shellcode-dynamic](src/05-shellcode-dynamic.c):
same as the previous task, but here the stack address (and therefore the shellcode address on the stack) is unknown.

6. [06-system-rop](src/06-system-rop.c):
compose a ROP chain to execute `system("/bin/sh")`.

7. [07-execve-rop](src/07-execve-rop.c):
compose a ROP chain to execute `execve("/bin/sh", NULL, NULL)` via a syscall.
Explicitly specify the second and third arguments.

8. [08-overwrite-global](src/08-overwrite-global.c):
compose a ROP chain to overwrite `x` with the desired value and then jump to `not_called()`.


### Protections

Blank spaces mean the protection state is not relevant for the suggested approach.

| Task                                                 | Binary\* | Stack\* | Libc\* | Canary  | NX      | RELRO    |
| :---:                                                | :---:    | :---:   | :---:  | :---:   | :---:   | :---:    |
| [01-local-overflow](src/01-local-overflow.c)         |          |         |        | No      |         |          |
| [02-overwrite-ret](src/02-overwrite-ret.c)           | Known    |         | Known  | No      |         |          |
| [03-one-gadget](src/03-one-gadget.c)                 | Known    |         | Known  | No      |         |          |
| [04-shellcode-static](src/04-shellcode-static.c)     |          | Known   |        | No      | No      |          |
| [05-shellcode-dynamic](src/05-shellcode-dynamic.c)   | Known    |         | Known  | No      | No      |          |
| [06-system-rop](src/06-system-rop.c)                 | Known    |         | Known  | No      |         |          |
| [07-execve-rop](src/07-execve-rop.c)                 | Known    |         | Known  | No      |         |          |
| [08-overwrite-global](src/08-overwrite-global.c)     | Known    |         | Known  | No      |         |          |

__\*__ - refers to the address of the binary, stack or libc. This allows to specify a more fine-grained control than traditional ASLR/PIE.

To disable ALSR:

``` bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

To enable ASLR:

``` bash
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```


## Solutions

These solutions are provided only for reference and are not portable (they contain hardcoded addresses and offsets and were only tested in a single environment).

| Task  | x86   | x86-64 | arm   | arm64 | mips  | mips64 | ppc   | ppc64 | sparc64 |
| :---: | :---: | :---:  | :---: | :---: | :---: | :---:  | :---: | :---: | :---:   |
| [01-local-overflow](src/01-local-overflow.c) | [+](pwn/x86/01-local-overflow.py) | [+](pwn/x86-64/01-local-overflow.py) | [+](pwn/arm/01-local-overflow.py) | [+](pwn/arm64/01-local-overflow.py) | [+](pwn/mips/01-local-overflow.py) | [+](pwn/mips64/01-local-overflow.py) | [+](pwn/ppc/01-local-overflow.py) | [+](pwn/ppc64/01-local-overflow.py) | [+](pwn/sparc64/01-local-overflow.py) |
| [02-overwrite-ret](src/02-overwrite-ret.c) | [+](pwn/x86/02-overwrite-ret.py) | [+](pwn/x86-64/02-overwrite-ret.py) | [+](pwn/arm/02-overwrite-ret.py) | [+](pwn/arm64/02-overwrite-ret.py) | [+](pwn/mips/02-overwrite-ret.py) | [+](pwn/mips64/02-overwrite-ret.py) | [+](pwn/ppc/02-overwrite-ret.py) | [+](pwn/ppc64/02-overwrite-ret.py) | [+](pwn/sparc64/02-overwrite-ret.py) |
| [03-one-gadget](src/03-one-gadget.c) | [+](pwn/x86/03-one-gadget.py) | [+](pwn/x86-64/03-one-gadget.py) | | [+](pwn/arm64/03-one-gadget.py) | | | | | |
| [04-shellcode-static](src/04-shellcode-static.c) | [+](pwn/x86/04-shellcode-static.py) | [+](pwn/x86-64/04-shellcode-static.py) | [+](pwn/arm/04-shellcode-static.py) | [+](pwn/arm64/04-shellcode-static.py) | [+](pwn/mips/04-shellcode-static.py) | [+](pwn/mips64/04-shellcode-static.py) | [+](pwn/ppc/04-shellcode-static.py) | [+](pwn/ppc64/04-shellcode-static.py) | |
| [05-shellcode-dynamic](src/05-shellcode-dynamic.c) | [+](pwn/x86/05-shellcode-dynamic.py) | [+](pwn/x86-64/05-shellcode-dynamic.py) | [+](pwn/arm/05-shellcode-dynamic.py) | [+](pwn/arm64/05-shellcode-dynamic.py) | [+](pwn/mips/05-shellcode-dynamic.py) | [+](pwn/mips64/05-shellcode-dynamic.py) | [+](pwn/ppc/05-shellcode-dynamic.py) | | |
| [06-system-rop](src/06-system-rop.c) | [+](pwn/x86/06-system-rop.py) | [+](pwn/x86-64/06-system-rop.py) | [+](pwn/arm/06-system-rop.py) | [+](pwn/arm64/06-system-rop.py) | [+](pwn/mips/06-system-rop.py) | [+](pwn/mips64/06-system-rop.py) | [+](pwn/ppc/06-system-rop.py) | [+](pwn/ppc64/06-system-rop.py) | |
| [07-execve-rop](src/07-execve-rop.c) | [+](pwn/x86/07-execve-rop.py) | [+](pwn/x86-64/07-execve-rop.py) | [+](pwn/arm/07-execve-rop.py) | [+](pwn/arm64/07-execve-rop.py) | [+](pwn/mips/07-execve-rop.py) | [+](pwn/mips64/07-execve-rop.py) | [+](pwn/ppc/07-execve-rop.py) | [+](pwn/ppc64/07-execve-rop.py) | |
| [08-overwrite-global](src/08-overwrite-global.c) | [+](pwn/x86/08-overwrite-global.py) | [+](pwn/x86-64/08-overwrite-global.py) | [+](pwn/arm/08-overwrite-global.py) | [+](pwn/arm64/08-overwrite-global.py) | [+](pwn/mips/08-overwrite-global.py) | [+](pwn/mips64/08-overwrite-global.py) | [+](pwn/ppc/08-overwrite-global.py) | [+](pwn/ppc64/08-overwrite-global.py) | |


## Prerequisites

The tasks were tested on x86-64 CPU machine with Linux Mint 19.1 and the following software versions:

| Software | Version                                  |
| :---:    | :---:                                    |
| GCC      | (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0     |
| glibc    | (Ubuntu GLIBC 2.27-3ubuntu1) 2.27        |
| QEMU     | 2.11.1(Debian 1:2.11+dfsg-1ubuntu7.12)   |
| GDB      | (Ubuntu 8.1-0ubuntu3) 8.1.0.20180409-git |
| pwntools | 3.12.2                                   |
| Ropper   | 1.11.13                                  |

Issues:

1. `qemu-ppc64` requires a newer QEMU (with [this](https://patchwork.kernel.org/patch/10243489/) patch), so you'll need to build QEMU from source.
If the manually built QEMU doesn't know where to look for dynamic libs, run `export QEMU_LD_PREFIX=/etc/qemu-binfmt/ppc64/` before using `pwntools`.

2. `ropper` has poor support for `ppc` and `ppc64`, so [this](https://github.com/sashs/Ropper/pull/98) patch is recommended to recognize more gadgets.

3. `ropper` doesn't recognize `ppc64` binaries automatically and requires [this](https://github.com/sashs/Ropper/pull/100) patch (you may also explicitly provide `--arch PPC64`).

4. `pwntools` doesn't set arch name for GDB for `sparc64` correctly and requires [this](https://github.com/Gallopsled/pwntools/pull/1292) patch.

5. `ropper` (nor `ROPgadget`) doesn't support `sparc64` and requires [this](https://github.com/sashs/Ropper/pull/101) patch.


### Setup

Install packages:

``` bash
sudo apt-get install build-essential
sudo apt-get install gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu gcc-mips-linux-gnu gcc-mips64-linux-gnuabi64 gcc-powerpc-linux-gnu gcc-powerpc64-linux-gnu gcc-sparc64-linux-gnu
sudo apt-get install libc6-dev:i386 libc6-armhf-cross libc6-arm64-cross libc6-mips-cross libc6-mips64-cross libc6-powerpc-cross libc6-ppc64-cross libc6-sparc64-cross
sudo apt-get install qemu-user
sudo apt-get install gdb gdb-multiarch

# These are probably not required, but just in case:
# sudo apt-get install gcc-7-multilib gcc-multilib-arm-linux-gnueabi gcc-multilib-mips-linux-gnu gcc-multilib-mips64-linux-gnuabi64 gcc-multilib-powerpc-linux-gnu gcc-multilib-powerpc64-linux-gnu
```

Build the binaries:

``` bash
./build.sh
```

Install pwntools and ropper (assuming that you have `pip` installed):

``` bash
pip install --user pwntools ropper
```

Setup `qemu-binfmt` for QEMU and pwntools:

``` bash
sudo mkdir /etc/qemu-binfmt
sudo ln -s /usr/arm-linux-gnueabihf/ /etc/qemu-binfmt/arm
sudo ln -s /usr/aarch64-linux-gnu /etc/qemu-binfmt/aarch64
sudo ln -s /usr/mips-linux-gnu/ /etc/qemu-binfmt/mips
sudo ln -s /usr/mips64-linux-gnuabi64/ /etc/qemu-binfmt/mips64
sudo ln -s /usr/powerpc-linux-gnu/ /etc/qemu-binfmt/ppc
sudo ln -s /usr/powerpc64-linux-gnu/ /etc/qemu-binfmt/ppc64
sudo ln -s /usr/sparc64-linux-gnu/ /etc/qemu-binfmt/sparc64
```


### More

In case you want to run the binaries and QEMU manually:

``` bash
gdbserver --no-disable-randomization localhost:1234 ./bin/x86/00-hello-pwn
gdbserver --no-disable-randomization localhost:1234 ./bin/x86-64/00-hello-pwn
qemu-arm -L /usr/arm-linux-gnueabihf/ -g 1234 ./bin/arm/00-hello-pwn
qemu-aarch64 -L /usr/aarch64-linux-gnu/ -g 1234 ./bin/arm64/00-hello-pwn
qemu-mips -L /usr/mips-linux-gnu/ -g 1234 ./bin/mips/00-hello-pwn
qemu-mips64 -L /usr/mips64-linux-gnuabi64/ -g 1234 ./bin/mips64/00-hello-pwn
qemu-ppc -L /usr/powerpc-linux-gnu/ -g 1234 ./bin/ppc/00-hello-pwn
qemu-ppc64 -L /usr/powerpc64-linux-gnu/ -g 1234 ./bin/ppc64/00-hello-pwn
qemu-sparc64 -L /usr/sparc64-linux-gnu/ -g 1234 ./bin/sparc64/00-hello-pwn
```

``` bash
gdb -q -ex "set architecture i386" -ex "set solib-search-path /lib/i386-linux-gnu/" -ex "target remote localhost:1234" ./bin/x86/00-hello-pwn
gdb -q -ex "target remote localhost:1234" ./bin/x86-64/00-hello-pwn
gdb-multiarch -q -ex "set architecture arm" -ex "set solib-absolute-prefix /usr/arm-linux-gnueabihf/" -ex "target remote localhost:1234" ./bin/arm/00-hello-pwn
gdb-multiarch -q -ex "set architecture aarch64" -ex "set solib-absolute-prefix /usr/aarch64-linux-gnu/" -ex "target remote localhost:1234" ./bin/arm64/00-hello-pwn
gdb-multiarch -q -ex "set architecture mips" -ex "set solib-absolute-prefix /usr/mips-linux-gnu/" -ex "target remote localhost:1234" ./bin/mips/00-hello-pwn
gdb-multiarch -q -ex "set architecture mips64" -ex "set solib-absolute-prefix /usr/mips64-linux-gnuabi64/" -ex "target remote localhost:1234" ./bin/mips64/00-hello-pwn
gdb-multiarch -q -ex "set architecture powerpc:common" -ex "set solib-absolute-prefix /usr/powerpc-linux-gnu/" -ex "target remote localhost:1234" ./bin/ppc/00-hello-pwn
gdb-multiarch -q -ex "set architecture powerpc:common64" -ex "set solib-absolute-prefix /usr/powerpc64-linux-gnu/" -ex "target remote localhost:1234" ./bin/ppc64/00-hello-pwn
gdb-multiarch -q -ex "set architecture sparc:v9" -ex "set solib-absolute-prefix /usr/sparc64-linux-gnu/" -ex "target remote localhost:1234" ./bin/sparc64/00-hello-pwn
```

If you want to do full system emulation, you can do that either manually via `qemu-system-*` or via [arm_now](https://github.com/nongiach/arm_now).


## Materials

I'm not aiming to provide a thoroughly collected list of materials to learn binary exploitation here, so for the most part you should rely on your own ability to find them.
I'll still put here some links that I have found helpful.

[Linux syscall tables](https://w3challs.com/syscalls/)

### x86 and x86-64

Countless tutorials available online for these architectures.

### arm

[INTRODUCTION TO ARM ASSEMBLY BASICS](https://azeria-labs.com/writing-arm-assembly-part-1/) [articles]

[ARM shellcode and exploit development](https://github.com/invictus1306/Workshop-BSidesMunich2018/blob/master/workshop_slides.pdf) [slides]

### arm64

[ARM Architecture Reference Manual ARMv8, for ARMv8-A architecture profile](https://static.docs.arm.com/ddi0487/b/DDI0487B_a_armv8_arm.pdf) [book]

[Introduction to A64 Instruction Set](https://blog.linuxplumbersconf.org/2014/ocw//system/presentations/2361/original/02%20-%20a64-isa-intro-final.pdf) [slides]

[ROP-ing on Aarch64 - The CTF Style](https://blog.perfect.blue/ROPing-on-Aarch64) [article]

[GoogleCTF - forced-puns](https://0xabe.io/ctf/exploit/2016/05/02/GoogleCTF-forced-puns.html) [article]

### mips

[MIPS IV Instruction Set](http://math-atlas.sourceforge.net/devel/assembly/mips-iv.pdf) [book]

[MIPS Calling Convention](https://courses.cs.washington.edu/courses/cse410/09sp/examples/MIPSCallingConventionsSummary.pdf) [article]

[EXPLOITING BUFFER OVERFLOWS ON MIPS ARCHITECTURES](https://www.vantagepoint.sg/papers/MIPS-BOF-LyonYang-PUBLIC-FINAL.pdf) [article]

[Exploiting a MIPS Stack Overflow](http://www.devttys0.com/2012/10/exploiting-a-mips-stack-overflow/) [article]

Notes:

1. `mips` has branch delay slot.

### mips64

[MIPS64 Architecture For Programmers Volume II: The MIPS64 Instruction Set](https://scc.ustc.edu.cn/zlsc/lxwycj/200910/W020100308600769158777.pdf) [book]

[Linux MIPS ELF reverse engineering tips](https://www.cr0.org/paper/mips.elf.external.resolution.txt) [article]

Notes:

1. `mips64` has branch delay slot.

2. Functions expect to be called through `$t9`.

### ppc

[PowerPC User Instruction Set Architecture Book I Version 2.01](http://math-atlas.sourceforge.net/devel/assembly/ppc_isa.pdf) [book]

[POWERPC FUNCTION CALLING CONVENTION](https://g4laad.re/part-6-powerpc-stack-and-function/) [article]

[Router Exploitation](https://www.recurity-labs.com/research/FX_Router_Exploitation.pdf) [slides]

[CVE-2017-3881 Cisco Catalyst RCE Proof-Of-Concept](https://artkond.com/2017/04/10/cisco-catalyst-remote-code-execution/) [article]

[How To Cook Cisco](https://embedi.org/blog/how-cook-cisco/) [article]

### ppc64

[PowerPC User Instruction Set Architecture Book I Version 2.01](http://math-atlas.sourceforge.net/devel/assembly/ppc_isa.pdf) [book]

[64-bit PowerPC ELF Application Binary Interface Supplement 1.9](https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.html) [article]

[Deeply understand 64-bit PowerPC ELF ABI - Function Descriptors](https://www.ibm.com/developerworks/community/blogs/5894415f-be62-4bc0-81c5-3956e82276f3/entry/deeply_understand_64_bit_powerpc_elf_abi_function_descriptors?lang=en) [article]

Notes:

1. Functions expect a correct value of `$r2` when called.

### sparc

[The SPARC Architecture Manual Version 8](https://www.gaisler.com/doc/sparcv8.pdf) [book]

[Function Call and Return in SPARC combined with Sliding Register Windows](http://www.mathcs.emory.edu/~cheung/Courses/255/Syllabus/8-SPARC/func-call+ret.html) [article]

[When Good Instructions Go Bad: Generalizing Return-Oriented Programming to RISC](https://hovav.net/ucsd/dist/sparc.pdf) [paper]

[Buffer Overflows On the SPARC Architecture](http://www.davidlitchfield.com/sparc_buffer_overflows.pdf) [article]

### sparc64

[The SPARC Architecture Manual Version 9](https://cr.yp.to/2005-590/sparcv9.pdf) [book]

[SPARC V9 ABI Features](https://docs.oracle.com/cd/E19120-01/open.solaris/816-5138/advanced-2/index.html) [article]

Notes:

1. `sparc64` has branch delay slot.

2. `sparc64` has stack bias of 2047 bytes.

3. `sparc64` CPU used by QEMU has 8 register windows.

4. Figure out why and when `vulnerable()` register window gets loaded from the stack, none of the linked ROP tutorials mention it :)


## Someday

Some ideas for more tasks:

XX-dup2-rop,
XX-aaw-rop,
XX-format-string,
XX-reverse-shell,
XX-oneshot-write,
XX-oneshot-syscall,
XX-bruteforce-aslr,
XX-bruteforce-canary,
XX-overwrite-got,
XX-partial-ret,
XX-partial-got,
XX-sleep-shellcode,
XX-mprotect-shellcode,
XX-nonull-shellcode,
XX-alphanum-shellcode,
XX-shellcode-encoder,
XX-nop-sled,
XX-ret-sled,
XX-canary-master,
XX-canary-leak,
XX-magic-gadget,
XX-stack-pivot,
XX-egghunt
