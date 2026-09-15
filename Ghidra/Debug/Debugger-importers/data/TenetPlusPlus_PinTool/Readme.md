# Tenet++

The `tenetplusplus` pintool is an enhancement of the `pintenet` tracer found in
the [Tenet](https://github.com/gaasedelen/tenet) repo under the MIT license. With the Tenet++ tracer comes a new format
as well to enable some additional features when imported into Ghidra.

## New Format

Tenet++ expands the original tenet format to be better suited for additional features added to Ghidra.

### Example

```
Loaded image: 0x55b9ab65b000:0x55b9ab660d57 -> /usr/bin/whoami Bytes: 7f454c4602010100000000000000000003003e000100000020270000000000004000000000000000587600000000000000000000400038000d0040001e001d000600000004000000400000000000000040000000000000004000000000000000d802000000000000d80>
Loaded image: 0x7f78bd58d000:0x7f78bd5c38a7 -> /lib64/ld-linux-x86-64.so.2 Bytes: 7f454c4602010103000000000000000003003e000100000030ef0100000000004000000000000000684a0e000000000000000000400038000b004000230022000100000004000000000000000000000000000000000000000000000000000000301b000>
tid=0,rdi=0x7ffd3cbe5eb0,rsp=0x7ffd3cbe5eb0,rip=0x7f78bd5abf33
tid=0,rsp=0x7ffd3cbe5ea8,rip=0x7f78bd5acca0,mw=0x7ffd3cbe5ea8:38bf5abd787f0000
tid=0,rdi=0x6fffffff,rbp=0x7ffd3cbe5ea0,rsp=0x7ffd3cbe5e40,rbx=0x6ffffeff,rdx=0x7f78bd5c5e90,rcx=0x7f78bd5c6a70,rax=0xe,r8=0x70000022,r9=0x32,r10=0x6ffffdff,r11=0x6ffffe35,r12=0x7f78bd58d000,r13=0x6fffff41,r15=0x7ffd3cbe5eb0,rip=0x7f78bd5acd2d,ma=0x7f78bd5c5ac0:5ebb5be2a9520000,ma>
tid=0,rip=0x7f78bd5acd4a
tid=0,rsi=0x4c,rdx=0x7f78bd5c5eb0,rax=0x4c,r14=0xeffffef5,rip=0x7f78bd5ad089,ma=0x7f78bd5c5ea0:0400000000000000,ma=0x7f78bd5c5eb0:f5feff6f00000000,ma=0x7f78bd5c6a90:a05e5cbd787f0000,ma=0x7f78bd5c6ae0:905e5cbd787f0000
tid=0,rip=0x7f78bd5acd39
tid=0,rsi=0x29,rdx=0x7f78bd5c5f90,rax=0x7f78bd5c5eb0,rip=0x7f78bd5ad114,ma=0x7f78bd5c5ea8:f0d258bd787f0000,ma=0x7f78bd5c5eb8:38d458bd787f0000050000000000000090d958bd787f00000600000000000000a0d558bd787f00000a00000000000000,ma=0x7f78bd5c5ef0:0b00000000000000,ma=0x7f78bd5c5f00:070000>
tid=0,rip=0x7f78bd5acdaa
```

### Breakdown

A single line is a new snapshot/event and can be one of three types:

#### Instruction execution

* __tid=[thread id],[register name]=[value]...,m[r/w/a]=[address]:[bytes]...__
    * __tid=[thread id]__
        * Records which thread this event happens in
        * Required for every instruction event
        * eg. `tid=0`
    * __[register name]=[value]__
        * Records register assignments
        * 0 or more per line
        * eg. `rdi=0x7ffd3cbe5eb0`
    * __m[r/w/a]=[address]:[bytes]__
        * Records memory reads/writes as well as the coalesced memory from the `-rec_all_memory` option.
        * 0 or more per line
        * eg. `mw=0x7ffd3cbe5ea8:38bf5abd787f0000`

#### Image loading

* __Loaded image: [start address]:[end address] -> [module name] Bytes: [bytes starting from start address]__
    * Records when images are loaded into memory as well as the bytes that were loaded
    * eg. `Loaded image: 0x55b9ab65b000:0x55b9ab660d57 -> /usr/bin/whoami Bytes: 7f454c46020101000...`

#### Image unloading

* __Unloaded image: [start address]:[end address] -> [module name]__
    * Records when images are unloaded from memory
    * eg. `Unloaded image: 0x55b9ab65b000:0x55b9ab660d57 -> /usr/bin/whoami`

There can be a variable amount of actual time between events based on the recording granularity.

## Improvements made by Tenet++ pin tracer:

1. Trace start and stop addresses
    - These allow the user to precisely trace only certain points of a program
2. Trace granularity
    - These give the user an option to choose how granular the tracer is: Instruction, Block or Routine level
3. Record all memory
    - Even if using routine level tracing, the user can record all memory events that get coalesced and read prior to
      the
      next routine event. This ensures the event has an updated snapshot of modified memory
4. Record image bytes at image load time
5. Record all threads in process in a single trace

# Usage

The pintool can be used to trace simple usermode applications on Windows or Linux. To use it, provide the path for a
compiled version of `tenetplusplus` to `pin` via the `-t` argument.

Example usage:

```
C:\pin\pin -t obj-ia32\tenetplusplus.dll -- "C:\Users\user\Desktop\calc.exe"
```

This pintool will generate a single trace containing trace data from all threads.

## Additional parameters

* `-s` Start tracing when an [image name]:[image base offset] is hit
    * Example: `-s kernel32.dll:1234 -s app:2FFF`
* `-e ` Stop tracing when an [image name]:[image base offset] is hit
    * Example: `-e kernel32.dll:1234 -e app:2FFF`
* `-g` Trace granularity level, default is 2
    * `2` Instruction Level Tracing
    * `4` Basic Block Level Tracing
    * `8` Routine Level Tracing
* `-o` Prefix of the output .trace file, default is `trace`
* `-rec_all_memory` Record all memory r/w events regardless of granularity level until next log write
* `-w` Add a module to the whitelist. If none is specified, every module is white-listed
    * Example: `-w calc.exe`, or `-w calc.exe,kernel32.dll`

# Compilation

To compile the pintool, you first will need
to [download](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads) and extract Pin.

Follow the build instructions below for your respective platform.

## Building for Linux

On Linux, one can compile the pintool using the following commands.

```
cd <location where tenetplusplus.cpp is>

# Location where you extracted Pin
export PIN_ROOT=~/pin
export PATH=$PATH:$PIN_ROOT
make TARGET=intel64
make TARGET=ia32
```

## Building for Windows

Install deps for building Pintools:

- Install Visual Studio Community 2019 Edition
  from  [https://visualstudio.microsoft.com/downloads/](https://visualstudio.microsoft.com/downloads/)
    - Make sure to install the Desktop development for C++ workload

- Install GNU's make, version 4.2.1, using Cygwin's 64-bit installer. Cygwin installer link
  here:  [https://cygwin.com/install.html](https://cygwin.com/install.html)

### Building 32bit

1. Launch a new CMD window and paste the EXACT following:
   ```
   set PIN_ROOT=C:\\pin
   set PATH=%PATH%;C:\cygwin64\bin
   "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
   ```
2. Change to the directory containing the `tenetplusplus` source, build the 32bit pin tool:
   ```
   make TARGET=ia32
   ```

### Building 64bit

1. Launch a new CMD window and paste the EXACT following:
   ```
   set PIN_ROOT=C:\\pin
   set PATH=%PATH%;C:\cygwin64\bin
   "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
   ```
2. Change to the directory containing the `tenetplusplus` source, and build the 64bit pin tool:
   ```
   make TARGET=intel64
   ```