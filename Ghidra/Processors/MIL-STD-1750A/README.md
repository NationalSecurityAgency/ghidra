# MIL-STD-1750A

MIL-STD-1750A (USAF) 16-bit instruction set architecture, 2 July 1980, with Notice 1 (21 May 1982).

Covers the base instruction set: all instruction formats and addressing modes, integer, logical, shift, bit,
branch, stack, byte and I/O instructions, and 32-bit and 48-bit 1750A floating point (as pcodeops).
XIO commands from the standard are shown by name; the mandatory commands that act on MK, SW, PI and FT are
modeled. The processor spec labels the reset entry and the interrupt linkage and service pointers (table VIII).
The analyzer "MIL-STD-1750A Interrupt Vectors" follows the vector table at 20-3F and creates functions at the
interrupt handlers and the BEX entry points.

Two languages:

- `MIL-STD-1750A:BE:16:default`: 64K-word logical memory.
- `MIL-STD-1750A:BE:24:expanded`: expanded memory addressing (4.5.2). Memory is the 20-bit physical space;
  the page file (16 groups, instruction and operand sets, 16 page registers each) is the `pagefile` space,
  written and read by the WIPR, WOPR, RIPR and ROPR commands. Operand references use the operand set of the
  group in SW (AS); computed jumps and returns use the instruction set. Direct branch targets and return
  addresses stay in the 64K-word bank of the instruction (logical page n of the code is physical page
  16 * bank + n); sequential execution past the end of a bank continues at the next physical word. The access
  lock and key and the E/W bits are not checked.

Contributed by Laxmi Narayan Behera, LNB Federal Corporation, as a volunteer open source contribution. Not developed or paid for under any contract.
