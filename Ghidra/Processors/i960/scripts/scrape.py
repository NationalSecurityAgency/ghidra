#!/usr/bin/env python
"""Scrape the 2.30 binutils source code for 80960 (i960)"""

import sys
import struct

print("# i960 / 80960\n\n")
print("define endian=little;\n")
print("define alignment=4;\n")
print("define space ram type=ram_space size=4 default;\n")
print("define space register type=register_space size=4;\n\n")



# global g0-g15, local r0-r15
# g15 == fp
# r0 == pfp (previous frame pointer)
# r1 == sp
# r2 == rip
# sf0 (IPND)
# sf1 (IMSK)
# sf2 (DMAC)
registers = [
    "pfp", "sp",  "rip", "r3",  "r4",  "r5",  "r6",  "r7",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "g0",  "g1",  "g2",  "g3",  "g4",  "g5",  "g6",  "g7",
    "g8",  "g9",  "g10", "g11", "g12", "g13", "g14", "fp"
]

print("define register offset=0 size=4 [ %s ];\n\n" % ' '.join(registers))

sfregisters = [
    "sf0", "sf1", "sf2", "sf3", "sf4", "sf5", "sf6", "sf7",
    "sf8", "sf9", "sf10", "sf11", "sf12", "sf13", "sf14", "sf15",
    "sf16", "sf17", "sf18", "sf19", "sf20", "sf21", "sf22", "sf23",
    "sf24", "sf25", "sf26", "sf27", "sf28", "sf29", "sf30", "sf31"
]
print("define register offset=0x100 size=4 [ %s ];\n\n" % ' '.join(sfregisters))

# ip - instruction pointer
# ac - arithmetic controls
#    - AC.nif = 15 - no-imprecise-faults
#    - AC.om = 12 - integer overflow mask bit
#    - AC.of = 8 - integer overflow flag
#    - AC.cc = cc2 = 2
#            = cc1 = 1
#            = cc0 = 0
#    true/fale ===  010/000
#    unordered(false)/greater than(true)/equal/less than === 000/001/010/100
#    carryout/overflow === 01x/0x1
# pc - process controls
# tc - trace controls
stateregisters = [
    "pc",  "ac",  "ip",  "tc",
]
print("define register offset=0x200 size=4 [ %s ];\n\n" % ' '.join(stateregisters))
    
fpregisters = [
    "fp0", "fp1", "fp2", "fp3"
]

print("define register offset=0x300 size=4 [ %s ];\n\n\n" % ' '.join(fpregisters))



# instruction token
print("define token instr (32)")
print("  op2431=(24,31)")
print("  reg1923=(19,23)")
print("  reg1923l=(19,23)")
print("  reg1923tq=(19,23)")
print("  sfr1923=(19,23)")
print("  sfr1923l=(19,23)")
print("  sfr1923tq=(19,23)")
print("  fp1923=(19,23)")
print("  op1923=(19,23)")
print("  reg1418=(14,18)")
print("  reg1418l=(14,18)")
print("  reg1418tq=(14,18)")
print("  sfr1418=(14,18)")
print("  sfr1418l=(14,18)")
print("  sfr1418tq=(14,18)")
print("  fp1418=(14,18)")
print("  op1418=(14,18)")
print("  m2=(13,13)")
print("  m1=(12,12)")
print("  m0=(11,11)")
print("  op0710=(7,10)")
print("  s1=(6,6)")
print("  s0=(5,5)")
print("  reg0004=(0,4)")
print("  reg0004l=(0,4)")
print("  reg0004tq=(0,4)")
print("  sfr0004=(0,4)")
print("  sfr0004l=(0,4)")
print("  sfr0004tq=(0,4)")
print("  fp0004=(0,4)")
print("  op0004=(0,4)")
print("  disp0212=(2,12)")
print("  t=(1,1)")
print("  s2=(0,0)")
print("  disp0223=(2,23)")
print("  op0000=(0,0)")
print("  mode1213=(12,13)")
print("  mode1011=(10,11)")
print("  offset0011=(0,11)")
print("  scale=(7,9)")
print("  op0506=(5,6)")
print(";\n\n")

# displacement token
print("define token instr2 (32)\n  disp0031=(0,31)\n;\n\n\n")

print("attach variables [ reg0004 reg1418 reg1923 ]")
print("                 [ %s ];\n" % (' '.join(registers)))
print("attach variables [ reg0004l reg1418l reg1923l ]")
print("                 [ %s _ ];\n" % (' _ '.join(registers[::2])))
print("attach variables [ reg0004tq reg1418tq reg1923tq ]")
print("                 [ %s _ _ _];\n\n" % (' _ _ _ '.join(registers[::4])))

print("attach variables [ sfr0004 sfr1418 sfr1923 ]")
print("                 [ %s ];\n" % (' '.join(sfregisters)))
print("attach variables [ sfr0004l sfr1418l sfr1923l ]")
print("                 [ %s _ ];\n" % (' _ '.join(sfregisters[::2])))
print("attach variables [ sfr0004tq sfr1418tq sfr1923tq ]")
print("                 [ %s _ _ _ ];\n\n" % (' _ _ _ '.join(sfregisters[::4])))

regtok = [["reg0004", "reg1418", "reg1923"],["reg0004l", "reg1418l", "reg1923l"],None,["reg0004tq", "reg1418tq", "reg1923tq"]]
sfrtok = [["sfr0004", "sfr1418", "sfr1923"],["sfr0004l", "sfr1418l", "sfr1923l"],None,["sfr0004tq", "sfr1418tq", "sfr1923tq"]]
fptok = ["fp0004", "fp1418", "fp1923"]
littok = ["op0004", "op1418", "op1923"]

# The constructors for global or local registers, floating point, special, or literal
# MMMSST
# 32121
# REG
# xx0x0- src1 is global or local reg
# xx1x0- src1 is a literal
# xx0x1- src1 is a sfr
# xx1x1- reserved
# x0x0x- src2 is a global or local reg
# x1x0x- src2 is a literal
# x0x1x- src2 is a sfr
# x1x1x- reserved
# 0xxxx- src/dst is a global or local reg
# COBR
# --00-x src1 src2 and dst are global or local reg
# --10-x src1 is a literal, src2 and dst are global or local reg
# --01-x src1 is a global or local reg, src2 and dst are sfr
# --11-0 src1 is a literal, src2 and dst are sfr
# COBR / CTRL
# --x-x0 outcome predicted true
# --x-x1 outcome predicted false
print("\n\n")

print("regS1: reg0004 is reg0004 & m2 & m1 & m0=0 & s1 & s0=0 { export reg0004; }")
print("regS1l: reg0004l is reg0004l & m2 & m1 & m0=0 & s1 & s0=0 { export reg0004l; }")
print("regS1tq: reg0004tq is reg0004tq & m2 & m1 & m0=0 & s1 & s0=0 { export reg0004tq; }")
print("regS1: op0004 is op0004 & m2 & m1 & m0=1 & s1 & s0=0 { export op0004; }")
print("regS1: sfr0004 is sfr0004 & m2 & m1 & m0=0 & s1 & s0=1 { export sfr0004; }")
print("regS1l: sfr0004l is sfr0004l & m2 & m1 & m0=0 & s1 & s0=1 { export sfr0004l; }")
print("regS1tq: sfr0004tq is sfr0004tq & m2 & m1 & m0=0 & s1 & s0=1 { export sfr0004tq; }")

print("regS2: reg1418 is reg1418 & m2 & m1=0 & m0 & s1=0 & s0 { export reg1418; }")
print("regS2l: reg1418l is reg1418l & m2 & m1=0 & m0 & s1=0 & s0 { export reg1418l; }")
print("regS2tq: reg1418tq is reg1418tq & m2 & m1=0 & m0 & s1=0 & s0 { export reg1418tq; }")
print("regS2: op1418 is op1418 & m2 & m1=1 & m0 & s1=0 & s0 { export op1418; }")
print("regS2: sfr1418 is sfr1418 & m2 & m1=0 & m0 & s1=1 & s0 { export sfr1418; }")
print("regS2l: sfr1418l is sfr1418l & m2 & m1=0 & m0 & s1=1 & s0 { export sfr1418l; }")
print("regS2tq: sfr1418tq is sfr1418tq & m2 & m1=0 & m0 & s1=1 & s0 { export sfr1418tq; }")

print("regSD: reg1923 is reg1923 & m2=0 & m1 & m0 & s1 & s0 { export reg1923; }")
print("regSDl: reg1923l is reg1923l & m2=0 & m1 & m0 & s1 & s0 { export reg1923l; }")
print("regSDtq: reg1923tq is reg1923tq & m2=0 & m1 & m0 & s1 & s0 { export reg1923tq; }")


print("cobrS1: reg0004 is reg0004 & m0=0 & s1=0 & t { export reg0004; }")
print("cobrS1l: reg0004l is reg0004 & m0=0 & s1=0 & t { export reg0004l; }")
print("cobrS1tq: reg0004tq is reg0004 & m0=0 & s1=0 & t { export reg0004tq; }")
print("cobrS2: reg1418 is reg1418 & m0=0 & s1=0 & t { export reg1418; }")
print("cobrS2l: reg1418l is reg1418l & m0=0 & s1=0 & t { export reg1418l; }")
print("cobrS2tq: reg1418tq is reg1418tq & m0=0 & s1=0 & t { export reg1418tq; }")
print("cobrSD:  reg1923 is reg1923 & m0=0 & s1=0 & t { export reg1923; }")
print("cobrSDl:  reg1923l is reg1923l & m0=0 & s1=0 & t { export reg1923l; }")
print("cobrSDtq:  reg1923tq is reg1923tq & m0=0 & s1=0 & t { export reg1923tq; }")

print("cobrS1: op0004 is op0004 & m0=1 & s1=0 & t { export op0004; }")
print("cobrS2: reg1418 is reg1418 & m0=1 & s1=0 & t { export reg1418; }")
print("cobrS2l: reg1418l is reg1418l & m0=1 & s1=0 & t { export reg1418l; }")
print("cobrS2tq: reg1418tq is reg1418tq & m0=1 & s1=0 & t { export reg1418tq; }")
print("cobrSD:  reg1923 is reg1923 & m0=1 & s1=0 & t { export reg1923; }")
print("cobrSDl:  reg1923l is reg1923l & m0=1 & s1=0 & t { export reg1923l; }")
print("cobrSDtq:  reg1923tq is reg1923tq & m0=1 & s1=0 & t { export reg1923tq; }")

print("cobrS1: reg0004 is reg0004 & m0=0 & s1=1 & t { export reg0004; }")
print("cobrS1l: reg0004l is reg0004l & m0=0 & s1=1 & t { export reg0004l; }")
print("cobrS1tq: reg0004tq is reg0004tq & m0=0 & s1=1 & t { export reg0004tq; }")
print("cobrS2: sfr1418 is sfr1418 & m0=0 & s1=1 & t { export sfr1418; }")
print("cobrS2l: sfr1418l is sfr1418l & m0=0 & s1=1 & t { export sfr1418l; }")
print("cobrS2tq: sfr1418tq is sfr1418tq & m0=0 & s1=1 & t { export sfr1418tq; }")
print("cobrSD:  sfr1923 is sfr1923 & m0=0 & s1=1 & t { export sfr1923; }")
print("cobrSDl:  sfr1923l is sfr1923l & m0=0 & s1=1 & t { export sfr1923l; }")
print("cobrSDtq:  sfr1923tq is sfr1923tq & m0=0 & s1=1 & t { export sfr1923tq; }")

print("cobrS1: op0004 is op0004 & m0=1 & s1=0 & t=0 { export op0004; }")
print("cobrS2: sfr1418 is sfr1418 & m0=1 & s1=1 & t=0 { export sfr1418; }")
print("cobrS2l: sfr1418l is sfr1418l & m0=1 & s1=1 & t=0 { export sfr1418l; }")
print("cobrS2tq: sfr1418tq is sfr1418tq & m0=1 & s1=1 & t=0 { export sfr1418tq; }")
print("cobrSD:  sfr1923 is sfr1923 & m0=1 & s1=1 & t=0 { export sfr1923; }")
print("cobrSDl:  sfr1923l is sfr1923l & m0=1 & s1=1 & t=0 { export sfr1923l; }")
print("cobrSDtq:  sfr1923tq is sfr1923tq & m0=1 & s1=1 & t=0 { export sfr1923tq; }")

print("\n\n")

I_BASE	=0x01	#/* 80960 base instruction set	*/
I_CX	=0x02	#/* 80960Cx instruction		*/
I_DEC	=0x04	#/* Decimal instruction		*/
I_FP	=0x08	#/* Floating point instruction	*/
I_KX	=0x10	#/* 80960Kx instruction		*/
I_MIL	=0x20	#/* Military instruction		*/
I_CASIM	=0x40	#/* CA simulator instruction	*/
I_CX2	=0x80	#/* Cx/Jx/Hx instructions	*/
I_JX	=0x100	#/* Jx/Hx instruction		*/
I_HX	=0x200	#/* Hx instructions		*/


# SEE D-2

# opcode  displacement  T  0
# 31..24  23..2         1  0
CTRL	=0

# opcode  src1   src2  M  displacement  T  S2
# 31..24  23.19  18.14 13 12.........2  1  0
COBR	=1
COJ	=2

# opcode  src/dst  src2  mode  opcode  sflags src1
# 31..24  23...19  18.14 13.11 10...7  6....5 4..0
REG	=3

# MEMA
# opcode  src/dst  abase  mode  offset0011
# 31..24  23...19  18.14  13.12 11...0

# MEMB -  ATTN: can be followed by 4 bytes
# opcode  src/dst  abase  mode  mode  scale  00  index
# 31..24  23...19  18.14  13.12 11.10 9...7  6.5 4...0

# SEE D-4
# 00   "offset0011"                   - MEMA
# 10   "offset0011(reg)"              - MEMA
# 0100 "(reg)"                    - MEMB
# 0101 "disp + 8 (ip)"            - MEMB + disp
# 0110 reserved
# 0111 "(reg1)[reg2 * scale]"     - MEMB
# 1100 "disp"                     - MEMB + disp
# 1101 "disp(reg)"                - MEMB + disp
# 1110 "disp[reg * scale]"        - MEMB + disp
# 1111 "disp(reg1)[reg2 * scale]" - MEMB + disp
MEM1	=4  
MEM2	=5
MEM4	=6
MEM8	=7
MEM12	=8
MEM16	=9
FBRA	=10
CALLJ	=11


M = 0x7f

# special function register (sf0 ... sf2)
SFR	=0x10		#/* Mask for the "sfr-OK" bit */
# literal of the range 0 ... 31
LIT	=0x08		#/* Mask for the "literal-OK" bit */
# 
FP	=0x04		#/* Mask for "floating-point-OK" bit */



class OP():
    """Describes an operand to be used in the display and
    the bit pattern.
     * TODO  memory
     * registers
     * literal
     * special function register
     * floating point
    """
    def __init__(self,align,lit,fp,sfr):
        self.align = align
        self.lit = lit != 0
        self.fp = fp != 0
        self.sfr = sfr != 0 | (align != 0)
        self._index = None
        self._total = None
        self._fmt = None

    def val(self):
        sizes = ["", "l", 0, "tq"]
        if self._total == 3:
            position = ["S1", "S2", "SD"]
        elif self._total == 2:
            position = ["S1", "SD"]
        elif self._total == 1:
            position = ["SD"]
        else:
            raise ValueError("bad total number %d" % (self._total))
        
        if self._fmt == REG:
            return "reg" + position[self._index] + sizes[self.align]
        elif self._fmt == COBR:
            return "cobr" + position[self._index] + sizes[self.align]
        elif self._fmt in [MEM1,MEM2,MEM4,MEM8,MEM12,MEM16]:
            return "reg1923" + sizes[self.align]
        else:
            _ = "oper%x%x%x_%x%x%x%x" % (self._fmt, self._index, self._total,
                                         self.align, self.lit, self.fp, self.sfr)
            # print("# RETURNING: %s" % (_))
            return None

    @property
    def index(self):
        return self._index
    @property
    def total(self):
        return self._total
    @property
    def fmt(self):
        return self._fmt
    @index.setter
    def index(self, val):
        self._index = val
    @total.setter
    def total(self, val):
        self._total = val
    @fmt.setter
    def fmt(self, val):
        self._fmt = val



def R():
    return OP( 0, 0,   0,  0   )
def RS():
    return OP( 0, 0,   0,  SFR )
def RL():
    return OP( 0, LIT, 0,  0   )
def RSL():
    return OP( 0, LIT, 0,  SFR )
def F():
    return OP( 0, 0,   FP, 0   )
def FL():
    return OP( 0, LIT, FP, 0   )
def R2():
    return OP( 1, 0,   0,  0   )
def RL2():
    return OP( 1, LIT, 0,  0   )
def F2():
    return OP( 1, 0,   FP, 0   )
def FL2():
    return OP( 1, LIT, FP, 0   )
def R4():
    return OP( 3, 0,   0,  0   )
def RL4():
    return OP( 3, LIT, 0,  0   )
def F4():
    return OP( 3, 0,   FP, 0   )
def FL4():
    return OP( 3, LIT, FP, 0   )

# SEE E-1


#TODO  these should probably only be included in the table constructors
#      for the operands
def M1(opc):
    opc.bitpattern["m0"]=1
def M2(opc):
    opc.bitpattern["m1"]=1
def M3(opc):
    opc.bitpattern["m2"]=1
def S1(opc):
    opc.bitpattern["s0"]=1
def S2(opc):
    opc.bitpattern["s1"]=1

def COBR_OPC(opc):
    """generate the 8-bit opcode for COBR format"""
    opc.bitpattern["op2431"] = opc.op
    
def REG_OPC(opc):
    """generate the 12-bit opcode for a REG format"""
    opc.bitpattern["op2431"] = (opc.op >> 4) & 0xff
    opc.bitpattern["op0710"] = opc.op & 0x0f
    
def R_0(opc):
    """No operands"""
    # REG_OPC(opc)
    M1(opc)
    M2(opc)
    M3(opc)
    

def R_1(opc):
    """1 operand: src1"""
    # REG_OPC(opc)
    M2(opc)
    M3(opc)

def R_1D(opc):
    """1 operand: dst"""
    # REG_OPC(opc)
    M1(opc)
    M2(opc)

def R_2(opc):
    """2 ops: src1/src2"""
    # REG_OPC(opc)
    M3(opc)

def R_2D(opc):
    """2 ops: src1/dst"""
    # REG_OPC(opc)
    M2(opc)

def R_3(opc):
    """3 operands"""
    # REG_OPC(opc)


global_tables = []


def do_global(tbl):
    """print the tbl"""
    if tbl in ["m0", "m1", "m2", "s0", "s1", "disp0212", "disp0223", "op2431", "op0710", "op0000"]:
        return ""
    elif tbl.startswith("regS") or tbl.startswith("regSD") or tbl.startswith("reg1923") or tbl.startswith("cobr"):
        return ""
    elif tbl.startswith("oper"):
        tables = []
        # "oper%x%x%x_%x%x%x%x" % (fmt, index, total, self.align, self.lit, self.fp, self.sfr)
        fmt = int(tbl[4], 16)
        index = int(tbl[5], 10)
        total = int(tbl[6], 10)
        align = int(tbl[8], 10)
        lit = int(tbl[9], 10)
        fp = int(tbl[10], 10)
        sfr = int(tbl[11], 10)

        # every oper* is a REG
        if index == 2:
            tmpA = "%s: %s is %s & m%d=0 { export %s; }"
            tmpB =(tbl,regtok[align][index],regtok[align][index],index,regtok[align][index])
            tables.append(tmpA % tmpB)
        else:
            tmpA = "%s: %s is %s & m%d=0 & s%d=0 { export %s; }"
            tmpB =(tbl,regtok[align][index],regtok[align][index],index,index,regtok[align][index])
            tables.append(tmpA % tmpB)
        if sfr:
            if index == 2:
                tmpA = "%s: %s is %s & m%d=1 { export %s; }"
                tmpB =(tbl,sfrtok[align][index],sfrtok[align][index],index,sfrtok[align][index])
                tables.append(tmpA % tmpB)
            else:
                tmpA = "%s: %s is %s & m%d=0 & s%d=1 { export %s; }"
                tmpB =(tbl,sfrtok[align][index],sfrtok[align][index],index,index,sfrtok[align][index])
                tables.append(tmpA % tmpB)
        #TODO  need a FP manual, not doing this now
        # if fp:
        #     tmpA = "%s: %s is %s & m%d=0 & s%d=0 { export %s; }"
        #     tmpB =(tbl,sfrtok[index],sfrtok[index],index,index,sfrtok[index])
        #     tables.append(tmpA % tmpB)
        if lit:
            if index == 2:
                tmpA = "%s: %s is %s & m%d=1 { export %s; }"
                tmpB =(tbl,littok[index],littok[index],index,littok[index])
                tables.append(tmpA % tmpB)
            else:
                tmpA = "%s: %s is %s & m%d=1 & s%d=0 { export %s; }"
                tmpB =(tbl,littok[index],littok[index],index,index,littok[index])
                tables.append(tmpA % tmpB)
                
        return '\n'.join(tables)
    elif tbl.startswith("efa"):
        """handle efa1, 2, 4, 8, 12, and 16"""
        # subtables could be useful here, at least reg*scal
        size = tbl[3:]
        efa = []
        # offset0011
        tmpA = "%s: offset0011 is offset0011 & mode1213=0 { export *[ram]:%s offset0011; }"
        tmpB = (tbl, size)
        efa.append(tmpA % tmpB)
        # offset0011(reg)
        tmpA = "%s: offset0011 (reg1418) is offset0011 & reg1418 & mode1213=2 { local tmp:4 = reg1418 + offset0011; export *[ram]:%s tmp; }"
        tmpB = (tbl, size)
        efa.append(tmpA % tmpB)
        # (reg)
        tmpA = "%s: (reg1418) is reg1418 & mode1213=1 & mode1011=0 & op0506=0 { local tmp:4 = reg1418; export *[ram]:%s tmp; }"
        tmpB = (tbl, size)
        efa.append(tmpA % tmpB)
        # disp + 8 (ip)
        tmpA = "%s: reloc (ip) is ip & mode1213=1 & mode1011=1 & op0506=0 ; disp0031 [ reloc = disp0031 + 8; ] { local tmp:4 = reloc + inst_start; export *[ram]:%s tmp; }"
        tmpB = (tbl, size)
        efa.append(tmpA % tmpB)
        # (reg1)[reg2 * scale]
        tmpA = "%s: (reg1418) [reg0004 * scale] is scale & reg0004 & reg1418  & mode1213=1 & mode1011=3 & op0506=0 { local tmp:4 = (scale * reg0004) + reg1418; export *[ram]:%s tmp; }"
        tmpB = (tbl, size)
        efa.append(tmpA % tmpB)
        # disp
        tmpA = "%s: disp0031 is mode1213=3 & mode1011=0 & op0506=0 ; disp0031 { local tmp:4 = disp0031; export *[ram]:%s tmp; }"
        tmpB = (tbl, size)
        efa.append(tmpA % tmpB)
        # disp (reg)
        tmpA = "%s: disp0031 (reg1418) is reg1418 & mode1213=3 & mode1011=1 & op0506=0 ; disp0031 { local tmp:4 = disp0031 + reg1418; export *[ram]:%s tmp; }"
        tmpB = (tbl, size)
        efa.append(tmpA % tmpB)
        # disp[reg * scale]
        tmpA = "%s: disp0031 [reg0004 * scale] is reg0004 & scale & mode1213=3 & mode1011=2 & op0506=0 ; disp0031 { local tmp:4 = disp0031 + (reg0004 * scale); export *[ram]:%s tmp; }"
        tmpB = (tbl, size)
        efa.append(tmpA % tmpB)
        # disp(reg)[reg * scale]
        tmpA = "%s: disp0031 (reg1418) [reg0004 * scale] is reg1418 & reg0004 & scale & mode1213=3 & mode1011=3 & op0506=0 ; disp0031 { local tmp:4 = disp0031 + reg1418 + (reg0004 * scale); export *[ram]:%s tmp; }"
        tmpB = (tbl, size)
        efa.append(tmpA % tmpB)
        return '\n'.join(efa)
    else:
        return "%s: is unimpl" % tbl


class Opcode():
    def __init__(self, x):
        self.op_parse = x[0]
        self.op = x[1]
        self.name = x[2]
        self.iclass = x[3]
        self.fmt = x[4]
        self.num_ops = x[5]
        self.operand = x[6]
        for _ in range(self.num_ops):
            if isinstance(self.operand[_], OP):
                self.operand[_].fmt = self.fmt
                self.operand[_].index = _
                self.operand[_].total = self.num_ops
        self.operands = []
        self.bitpattern = {}

        # do stuff
        self.parse()
        return

    def __str__(self):
        tmp = []
        efa = None
        for k,v in self.bitpattern.items():
            if isinstance(k, str) and v is None:
                tmp.append("%s" % (k))
            elif isinstance(k, str):
                tmp.append("%s=0x%x" % (k,v))
            else:
                tmp.append("op%02d%02d=0x%x" % (k[0], k[1], v))
        tmp2 = []
        for x in range(len(self.operands)):
            _ = self.operands[x]
            if isinstance(_, OP):
                # print("# tmp2 %s" % _.val())
                newbit = _.val()
                if newbit:
                    tmp2.append(newbit)
                    tmp.append(newbit)
            else:
                if _.startswith("efa"):
                    efa = _
                else:
                    tmp.append(_)
                tmp2.append(_)

        # print("# %r" % (tmp))
        bitpattern = " & ".join(tmp)
        if efa:
            bitpattern = "( %s ) ... & %s" % (bitpattern, efa)
        return ":%s %s is %s unimpl" % (self.name, ", ".join(tmp2), bitpattern)

    def CTRL_parse(self):
        """Add a targ that is -2**23 to 2**23-4 disp"""
        self.bitpattern["op2431"] = self.op
        if self.num_ops == 1:
            self.operands.append("disp0223")
        elif self.num_ops == 0:
            pass
        else:
            print("badness in CTRL parse")
            sys.exit(1)
        self.bitpattern["op0000"]=0
        return
    def COBR_parse(self):
        """Add a dst reg or src1, src2, and targ"""
        self.bitpattern["op2431"] = self.op
        if self.num_ops == 1:
            self.operands.append(self.operand[0])
        elif self.num_ops == 3:
            self.operands.append(self.operand[0])
            self.operands.append(self.operand[1])
            self.operands.append("disp0212")
        else:
            print("badness in cobr")
            sys.exit(1)
    def COJ_parse(self):
        pass

    def REG_parse(self):
        """src1=op0004, src2=op1418, src/dst=op1923"""

        self.bitpattern["op2431"] = (self.op >> 4) & 0xff
        self.bitpattern["op0710"] = self.op & 0x0f
    
        reg0 = self.operand[0]
        reg1 = self.operand[1]
        reg2 = self.operand[2]

        if self.num_ops == 0:
            return
        elif self.num_ops == 1:
            if not isinstance(reg0, OP) or isinstance(reg1, OP) or isinstance(reg2, OP):
                print("badness 1 reg" % (self.name))
                sys.exit(1)
            if "m1" in self.bitpattern.keys() and "m2" in self.bitpattern.keys():
                reg0.total = 3
            elif "m0" in self.bitpattern.keys() and "m1" in self.bitpattern.keys():
                reg0.total = 1
            self.operands.append(reg0)
        elif self.num_ops == 2:
            if not isinstance(reg0, OP) or not isinstance(reg1, OP) or isinstance(reg2, OP):
                print("badness 2 reg %s" % (self.name))
                sys.exit(1)
            self.operands.append(reg0)
            if "m2" in self.bitpattern.keys():
                # this is a hack, but this is the decision between using 1923 and 1418
                reg1.total = 3
            self.operands.append(reg1)
        elif self.num_ops == 3:
            if not isinstance(reg0, OP) or not isinstance(reg1, OP) or not isinstance(reg2, OP):
                print("badness 3 reg %s" % (self.name))
                sys.exit(1)
            self.operands.append(reg0)
            self.operands.append(reg1)
            self.operands.append(reg2)
        else:
            print("badness in REG_parse")
            sys.exit(1)
        return

    def MEM1_parse(self):
        """Add an effective address argument, operates on 1-byte"""
        self.bitpattern["op2431"] = self.op
        if self.num_ops == 2:
            if isinstance(self.operand[0], OP):
                self.operands.append(self.operand[0])
            else:
                self.operands.append("efa1")
            if isinstance(self.operand[1], OP):
                self.operands.append(self.operand[1])
            else:
                self.operands.append("efa1")
        elif self.num_ops == 1:
            if isinstance(self.operand[0], OP):
                self.operands.append(self.operand[0])
            else:
                self.operands.append("efa1")
        else:
            print("badness in MEM1 parse %s" % self)
            sys.exit(1)
    def MEM2_parse(self):
        """Add an effective address argument, operates on 2-byte"""
        self.bitpattern["op2431"] = self.op
        if self.num_ops != 2:
            print("badness in MEM2 parse")
            sys.exit(1)
        if isinstance(self.operand[0], OP):
                self.operands.append(self.operand[0])
        else:
            self.operands.append("efa2")
        if isinstance(self.operand[1], OP):
            self.operands.append(self.operand[1])
        else:
            self.operands.append("efa2")
    def MEM4_parse(self):
        """Add an effective address argument, operates on 4-byte"""
        self.bitpattern["op2431"] = self.op
        if self.num_ops != 2:
            print("badness in MEM4 parse")
            sys.exit(1)
        if isinstance(self.operand[0], OP):
                self.operands.append(self.operand[0])
        else:
            self.operands.append("efa4")
        if isinstance(self.operand[1], OP):
            self.operands.append(self.operand[1])
        else:
            self.operands.append("efa4")
    def MEM8_parse(self):
        """Add an effective address argument, operates on 8-byte"""
        self.bitpattern["op2431"] = self.op
        if self.num_ops != 2:
            print("badness in MEM8 parse")
            sys.exit(1)
        if isinstance(self.operand[0], OP):
                self.operands.append(self.operand[0])
        else:
            self.operands.append("efa8")
        if isinstance(self.operand[1], OP):
            self.operands.append(self.operand[1])
        else:
            self.operands.append("efa8")
    def MEM12_parse(self):
        """Add an effective address argument, operates on 12-byte"""
        self.bitpattern["op2431"] = self.op
        if self.num_ops != 2:
            print("badness in MEM12 parse")
            sys.exit(1)
        if isinstance(self.operand[0], OP):
                self.operands.append(self.operand[0])
        else:
            self.operands.append("efa12")
        if isinstance(self.operand[1], OP):
            self.operands.append(self.operand[1])
        else:
            self.operands.append("efa12")
    def MEM16_parse(self):
        """Add an effective address argument, operates on 16-byte"""
        self.bitpattern["op2431"] = self.op
        if self.num_ops != 2:
            print("badness in MEM16 parse")
            sys.exit(1)
        if isinstance(self.operand[0], OP):
                self.operands.append(self.operand[0])
        else:
            self.operands.append("efa16")
        if isinstance(self.operand[1], OP):
            self.operands.append(self.operand[1])
        else:
            self.operands.append("efa16")
    # def FBRA_parse(self):
    #     pass
    # def CALLJ_parse(self):
    #     pass
                                                                                        
    def parse(self):
        # broke this 
        # self.op_parse(self)
        if self.op_parse in [R_0, R_1, R_1D, R_2, R_2D, R_3]:
            self.op_parse(self)
        
        if self.fmt == CTRL: self.CTRL_parse()
        elif self.fmt == COBR: self.COBR_parse()
        elif self.fmt == COJ: self.COJ_parse()
        elif self.fmt == REG: self.REG_parse()
        elif self.fmt == MEM1: self.MEM1_parse()
        elif self.fmt == MEM2: self.MEM2_parse()
        elif self.fmt == MEM4: self.MEM4_parse()
        elif self.fmt == MEM8: self.MEM8_parse()
        elif self.fmt == MEM12: self.MEM12_parse()
        elif self.fmt == MEM16: self.MEM16_parse()
        # elif self.fmt == FBRA: self.FBRA_parse()
        # elif self.fmt == CALLJ: self.CALLJ_parse()
        else:
            print("badness %r" % (self.fmt))
            sys.exit(1)
        global global_tables
        
        for k,v in self.bitpattern.items():
            if isinstance(k, str):
                global_tables.append("%s" % (k))
            else:
                global_tables.append("op%02d%02d" % (k[0], k[1]))
        for x in range(len(self.operands)):
            _ = self.operands[x]
            if isinstance(_, OP):
                new_global = _.val()
                if new_global:
                    global_tables.append(new_global)
            else:
                global_tables.append(_)
        global_tables = list(set(global_tables))

        return

    def __lt__(self, other):
        return self.name < other.name
    def __eq__(self, other):
        return self.name == other.name
    def __gt__(self, other):
        return self.name > other.name
        
    
opcodes = [
	# /* callj default=='call' */
	# ( COBR_OPC, 0x09, "callj",	I_BASE,	CALLJ, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x08, "b",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x09, "call",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x0a, "ret",		I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x0b, "bal",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x10, "bno",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* bf same as bno */
	# ( COBR_OPC, 0x10, "bf",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* bru same as bno */
	# ( COBR_OPC, 0x10, "bru",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x11, "bg",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* brg same as bg */
	# ( COBR_OPC, 0x11, "brg",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x12, "be",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* bre same as be */
	# ( COBR_OPC, 0x12, "bre",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x13, "bge",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* brge same as bge */
	# ( COBR_OPC, 0x13, "brge",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x14, "bl",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* brl same as bl */
	# ( COBR_OPC, 0x14, "brl",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x15, "bne",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* brlg same as bne */
	# ( COBR_OPC, 0x15, "brlg",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x16, "ble",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* brle same as ble */
	# ( COBR_OPC, 0x16, "brle",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x17, "bo",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* bt same as bo */
	# ( COBR_OPC, 0x17, "bt",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	# /* bro same as bo */
	# ( COBR_OPC, 0x17, "bro",		I_BASE,	CTRL, 	1, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x18, "faultno",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	# /* faultf same as faultno */
	# ( COBR_OPC, 0x18, "faultf",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x19, "faultg",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x1a, "faulte",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x1b, "faultge",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x1c, "faultl",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x1d, "faultne",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x1e, "faultle",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	( COBR_OPC, 0x1f, "faulto",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),
	# /* faultt syn for faulto */
	# ( COBR_OPC, 0x1f, "faultt",	I_BASE,	CTRL, 	0, ( 0, 0, 0 ) ),

	( COBR_OPC, 0x01, "syscall",	I_CASIM,CTRL, 	0, ( 0, 0, 0 ) ),

	# /* If a COBR (or COJ) has 3 operands, the last one is always a
	# * displacement and does not appear explicitly in the table.
	# */

	( COBR_OPC, 0x20, "testno",	I_BASE,	COBR,	1, ( R(), 0, 0 )	),
	( COBR_OPC, 0x21, "testg",	I_BASE,	COBR,	1, ( R(), 0, 0 )	),
	( COBR_OPC, 0x22, "teste",	I_BASE,	COBR,	1, ( R(), 0, 0 )	),
	( COBR_OPC, 0x23, "testge",	I_BASE,	COBR,	1, ( R(), 0, 0 )	),
	( COBR_OPC, 0x24, "testl",	I_BASE,	COBR,	1, ( R(), 0, 0 )	),
	( COBR_OPC, 0x25, "testne",	I_BASE,	COBR,	1, ( R(), 0, 0 )	),
	( COBR_OPC, 0x26, "testle",	I_BASE,	COBR,	1, ( R(), 0, 0 )	),
	( COBR_OPC, 0x27, "testo",	I_BASE,	COBR,	1, ( R(), 0, 0 )	),
	( COBR_OPC, 0x30, "bbc",		I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x31, "cmpobg",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x32, "cmpobe",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x33, "cmpobge",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x34, "cmpobl",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x35, "cmpobne",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x36, "cmpoble",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x37, "bbs",		I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x38, "cmpibno",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x39, "cmpibg",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x3a, "cmpibe",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x3b, "cmpibge",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x3c, "cmpibl",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x3d, "cmpibne",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x3e, "cmpible",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
	( COBR_OPC, 0x3f, "cmpibo",	I_BASE,	COBR,	3, ( RL(), RS(), 0 ) ),
        # COJ is just COBR with 'j' instead of 'b', this is an de-optimization instruction
	# ( REG_OPC, 0x310, "cmpojg",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x320, "cmpoje",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x330, "cmpojge",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x340, "cmpojl",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x350, "cmpojne",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x360, "cmpojle",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x380, "cmpijno",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x390, "cmpijg",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x3a0, "cmpije",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x3b0, "cmpijge",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x3c0, "cmpijl",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x3d0, "cmpijne",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x3e0, "cmpijle",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),
	# ( REG_OPC, 0x3f0, "cmpijo",	I_BASE,	COJ,	3, ( RL(), RS(), 0 ) ),

	( REG_OPC, 0x80, "ldob",		I_BASE,	MEM1,	2, ( M,  R(),  0 ) ),
	( REG_OPC, 0x82, "stob",		I_BASE,	MEM1,	2, ( R(),  M,  0 ) ),
	( REG_OPC, 0x84, "bx",		I_BASE,	MEM1,	1, ( M,  0,  0 ) ),
	( REG_OPC, 0x85, "balx",		I_BASE,	MEM1,	2, ( M,  R(),  0 ) ),
	( REG_OPC, 0x86, "callx",	I_BASE,	MEM1,	1, ( M,  0,  0 ) ),
	( REG_OPC, 0x88, "ldos",		I_BASE,	MEM2,	2, ( M,  R(),  0 ) ),
	( REG_OPC, 0x8a, "stos",		I_BASE,	MEM2,	2, ( R(),  M,  0 ) ),
	( REG_OPC, 0x8c, "lda",		I_BASE,	MEM1,	2, ( M,  R(),  0 ) ),
	( REG_OPC, 0x90, "ld",		I_BASE,	MEM4,	2, ( M,  R(),  0 ) ),
	( REG_OPC, 0x92, "st",		I_BASE,	MEM4,	2, ( R(),  M,  0 ) ),
	( REG_OPC, 0x98, "ldl",		I_BASE,	MEM8,	2, ( M,  R2(), 0 ) ),
	( REG_OPC, 0x9a, "stl",		I_BASE,	MEM8,	2, ( R2(), M,  0 ) ),
	( REG_OPC, 0xa0, "ldt",		I_BASE,	MEM12,	2, ( M,  R4(), 0 ) ),
	( REG_OPC, 0xa2, "stt",		I_BASE,	MEM12,	2, ( R4(), M,  0 ) ),
	( REG_OPC, 0xb0, "ldq",		I_BASE,	MEM16,	2, ( M,  R4(), 0 ) ),
	( REG_OPC, 0xb2, "stq",		I_BASE,	MEM16,	2, ( R4(), M,  0 ) ),
	( REG_OPC, 0xc0, "ldib",		I_BASE,	MEM1,	2, ( M,  R(),  0 ) ),
	( REG_OPC, 0xc2, "stib",		I_BASE,	MEM1,	2, ( R(),  M,  0 ) ),
	( REG_OPC, 0xc8, "ldis",		I_BASE,	MEM2,	2, ( M,  R(),  0 ) ),
	( REG_OPC, 0xca, "stis",		I_BASE,	MEM2,	2, ( R(),  M,  0 ) ),

	( R_3, 0x580, "notbit",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x581, "and",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x582, "andnot",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x583, "setbit",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x584, "notand",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x586, "xor",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x587, "or",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x588, "nor",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x589, "xnor",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_2D, 0x58a, "not",		I_BASE,	REG,	2, ( RSL(), RS(), 0 ) ),
	( R_3, 0x58b, "ornot",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x58c, "clrbit",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x58d, "notor",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x58e, "nand",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x58f, "alterbit",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x590, "addo",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x591, "addi",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x592, "subo",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x593, "subi",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x598, "shro",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x59a, "shrdi",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x59b, "shri",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x59c, "shlo",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x59d, "rotate",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x59e, "shli",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_2, 0x5a0, "cmpo",		I_BASE,	REG,	2, ( RSL(), RSL(), 0 ) ),
	( R_2, 0x5a1, "cmpi",		I_BASE,	REG,	2, ( RSL(), RSL(), 0 ) ),
	( R_2, 0x5a2, "concmpo",	I_BASE,	REG,	2, ( RSL(), RSL(), 0 ) ),
	( R_2, 0x5a3, "concmpi",	I_BASE,	REG,	2, ( RSL(), RSL(), 0 ) ),
	( R_3, 0x5a4, "cmpinco",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x5a5, "cmpinci",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x5a6, "cmpdeco",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x5a7, "cmpdeci",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_2, 0x5ac, "scanbyte",	I_BASE,	REG,	2, ( RSL(), RSL(), 0 ) ),
	( R_2, 0x5ae, "chkbit",	I_BASE,	REG,	2, ( RSL(), RSL(), 0 ) ),
	( R_3, 0x5b0, "addc",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x5b2, "subc",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_2D, 0x5cc, "mov",		I_BASE,	REG,	2, ( RSL(), RS(), 0 ) ),
	( R_2D, 0x5dc, "movl",		I_BASE,	REG,	2, ( RL2(), R2(), 0 ) ),
	( R_2D, 0x5ec, "movt",		I_BASE,	REG,	2, ( RL4(), R4(), 0 ) ),
	( R_2D, 0x5fc, "movq",		I_BASE,	REG,	2, ( RL4(), R4(), 0 ) ),
	( R_3, 0x610, "atmod",	I_BASE,	REG,	3, ( RS(), RSL(), R() ) ),
	( R_3, 0x612, "atadd",	I_BASE,	REG,	3, ( RS(), RSL(), RS() ) ),
	( R_2D, 0x640, "spanbit",	I_BASE,	REG,	2, ( RSL(), RS(), 0 ) ),
	( R_2D, 0x641, "scanbit",	I_BASE,	REG,	2, ( RSL(), RS(), 0 ) ),
	( R_3, 0x645, "modac",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x650, "modify",	I_BASE,	REG,	3, ( RSL(), RSL(), R() ) ),
	( R_3, 0x651, "extract",	I_BASE,	REG,	3, ( RSL(), RSL(), R() ) ),
	( R_3, 0x654, "modtc",	I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x655, "modpc",	I_BASE,	REG,	3, ( RSL(), RSL(), R() ) ),
	( R_1, 0x660, "calls",	I_BASE,	REG,	1, ( RSL(), 0, 0 ) ),
	( R_0, 0x66b, "mark",		I_BASE,	REG,	0, ( 0, 0, 0 )	),
	( R_0, 0x66c, "fmark",	I_BASE,	REG,	0, ( 0, 0, 0 )	),
	( R_0, 0x66d, "flushreg",	I_BASE,	REG,	0, ( 0, 0, 0 )	),
	( R_0, 0x66f, "syncf",	I_BASE,	REG,	0, ( 0, 0, 0 )	),
	( R_3, 0x670, "emul",		I_BASE,	REG,	3, ( RSL(), RSL(), R2() ) ),
	( R_3, 0x671, "ediv",		I_BASE,	REG,	3, ( RSL(), RL2(), RS() ) ),
	( R_2D, 0x672, "cvtadr",	I_CASIM,REG, 	2, ( RL(), R2(), 0 ) ),
	( R_3, 0x701, "mulo",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x708, "remo",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x70b, "divo",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x741, "muli",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x748, "remi",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x749, "modi",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x74b, "divi",		I_BASE,	REG,	3, ( RSL(), RSL(), RS() ) ),

	# /* Floating-point instructions */

	( R_2D, 0x674, "cvtir",	I_FP,	REG,	2, ( RL(), F(), 0 ) ),
	( R_2D, 0x675, "cvtilr",	I_FP,	REG,	2, ( RL(), F(), 0 ) ),
	( R_3, 0x676, "scalerl",	I_FP,	REG,	3, ( RL(), FL2(), F2() ) ),
	( R_3, 0x677, "scaler",	I_FP,	REG,	3, ( RL(), FL(), F() ) ),
	( R_3, 0x680, "atanr",	I_FP,	REG,	3, ( FL(), FL(), F() ) ),
	( R_3, 0x681, "logepr",	I_FP,	REG,	3, ( FL(), FL(), F() ) ),
	( R_3, 0x682, "logr",		I_FP,	REG,	3, ( FL(), FL(), F() ) ),
	( R_3, 0x683, "remr",		I_FP,	REG,	3, ( FL(), FL(), F() ) ),
	( R_2, 0x684, "cmpor",	I_FP,	REG,	2, ( FL(), FL(), 0 ) ),
	( R_2, 0x685, "cmpr",		I_FP,	REG,	2, ( FL(), FL(), 0 ) ),
	( R_2D, 0x688, "sqrtr",	I_FP,	REG,	2, ( FL(), F(), 0 ) ),
	( R_2D, 0x689, "expr",		I_FP,	REG,	2, ( FL(), F(), 0 ) ),
	( R_2D, 0x68a, "logbnr",	I_FP,	REG,	2, ( FL(), F(), 0 ) ),
	( R_2D, 0x68b, "roundr",	I_FP,	REG,	2, ( FL(), F(), 0 ) ),
	( R_2D, 0x68c, "sinr",		I_FP,	REG,	2, ( FL(), F(), 0 ) ),
	( R_2D, 0x68d, "cosr",		I_FP,	REG,	2, ( FL(), F(), 0 ) ),
	( R_2D, 0x68e, "tanr",		I_FP,	REG,	2, ( FL(), F(), 0 ) ),
	( R_1, 0x68f, "classr",	I_FP,	REG,	1, ( FL(), 0, 0 )	),
	( R_3, 0x690, "atanrl",	I_FP,	REG,	3, ( FL2(), FL2(), F2() ) ),
	( R_3, 0x691, "logeprl",	I_FP,	REG,	3, ( FL2(), FL2(), F2() ) ),
	( R_3, 0x692, "logrl",	I_FP,	REG,	3, ( FL2(), FL2(), F2() ) ),
	( R_3, 0x693, "remrl",	I_FP,	REG,	3, ( FL2(), FL2(), F2() ) ),
	( R_2, 0x694, "cmporl",	I_FP,	REG,	2, ( FL2(), FL2(), 0 ) ),
	( R_2, 0x695, "cmprl",	I_FP,	REG,	2, ( FL2(), FL2(), 0 ) ),
	( R_2D, 0x698, "sqrtrl",	I_FP,	REG,	2, ( FL2(), F2(), 0 ) ),
	( R_2D, 0x699, "exprl",	I_FP,	REG,	2, ( FL2(), F2(), 0 ) ),
	( R_2D, 0x69a, "logbnrl",	I_FP,	REG,	2, ( FL2(), F2(), 0 ) ),
	( R_2D, 0x69b, "roundrl",	I_FP,	REG,	2, ( FL2(), F2(), 0 ) ),
	( R_2D, 0x69c, "sinrl",	I_FP,	REG,	2, ( FL2(), F2(), 0 ) ),
	( R_2D, 0x69d, "cosrl",	I_FP,	REG,	2, ( FL2(), F2(), 0 ) ),
	( R_2D, 0x69e, "tanrl",	I_FP,	REG,	2, ( FL2(), F2(), 0 ) ),
	( R_1, 0x69f, "classrl",	I_FP,	REG,	1, ( FL2(), 0, 0 ) ),
	( R_2D, 0x6c0, "cvtri",	I_FP,	REG,	2, ( FL(), R(), 0 ) ),
	( R_2D, 0x6c1, "cvtril",	I_FP,	REG,	2, ( FL(), R2(), 0 ) ),
	( R_2D, 0x6c2, "cvtzri",	I_FP,	REG,	2, ( FL(), R(), 0 ) ),
	( R_2D, 0x6c3, "cvtzril",	I_FP,	REG,	2, ( FL(), R2(), 0 ) ),
	( R_2D, 0x6c9, "movr",		I_FP,	REG,	2, ( FL(), F(), 0 ) ),
	( R_2D, 0x6d9, "movrl",	I_FP,	REG,	2, ( FL2(), F2(), 0 ) ),
	( R_2D, 0x6e1, "movre",	I_FP,	REG,	2, ( FL4(), F4(), 0 ) ),
	( R_3, 0x6e2, "cpysre",	I_FP,	REG,	3, ( FL4(), FL4(), F4() ) ),
	( R_3, 0x6e3, "cpyrsre",	I_FP,	REG,	3, ( FL4(), FL4(), F4() ) ),
	( R_3, 0x78b, "divr",		I_FP,	REG,	3, ( FL(), FL(), F() ) ),
	( R_3, 0x78c, "mulr",		I_FP,	REG,	3, ( FL(), FL(), F() ) ),
	( R_3, 0x78d, "subr",		I_FP,	REG,	3, ( FL(), FL(), F() ) ),
	( R_3, 0x78f, "addr",		I_FP,	REG,	3, ( FL(), FL(), F() ) ),
	( R_3, 0x79b, "divrl",	I_FP,	REG,	3, ( FL2(), FL2(), F2() ) ),
	( R_3, 0x79c, "mulrl",	I_FP,	REG,	3, ( FL2(), FL2(), F2() ) ),
	( R_3, 0x79d, "subrl",	I_FP,	REG,	3, ( FL2(), FL2(), F2() ) ),
	( R_3, 0x79f, "addrl",	I_FP,	REG,	3, ( FL2(), FL2(), F2() ) ),

	# /* These are the floating point branch instructions.  Each actually
	# * generates 2 branch instructions:  the first a CTRL instruction with
	# * the indicated opcode, and the second a 'bno'.
	# */
        #TODO  not gonna mess with macro instructions
	# ( REG_OPC, 0x120, "brue",		I_FP,	FBRA, 	1, ( 0, 0, 0 )	),
	# ( REG_OPC, 0x110, "brug",		I_FP,	FBRA, 	1, ( 0, 0, 0 )	),
	# ( REG_OPC, 0x130, "bruge",	I_FP,	FBRA, 	1, ( 0, 0, 0 )	),
	# ( REG_OPC, 0x140, "brul",		I_FP,	FBRA, 	1, ( 0, 0, 0 )	),
	# ( REG_OPC, 0x160, "brule",	I_FP,	FBRA, 	1, ( 0, 0, 0 )	),
	# ( REG_OPC, 0x150, "brulg",	I_FP,	FBRA, 	1, ( 0, 0, 0 )	),


	# /* Decimal instructions */

	( R_3, 0x642, "daddc",	I_DEC,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x643, "dsubc",	I_DEC,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_2D, 0x644, "dmovt",	I_DEC,	REG,	2, ( RSL(), RS(), 0 ) ),


	# /* KX extensions */

	( R_2, 0x600, "synmov",	I_KX,	REG,	2, ( R(),  R(), 0 ) ),
	( R_2, 0x601, "synmovl",	I_KX,	REG,	2, ( R(),  R(), 0 ) ),
	( R_2, 0x602, "synmovq",	I_KX,	REG,	2, ( R(),  R(), 0 ) ),
	( R_2D, 0x615, "synld",	I_KX,	REG,	2, ( R(),  R(), 0 ) ),


	# /* MC extensions */

	( R_3, 0x603, "cmpstr",	I_MIL,	REG,	3, ( R(),  R(),  RL() ) ),
	( R_3, 0x604, "movqstr",	I_MIL,	REG,	3, ( R(),  R(),  RL() ) ),
	( R_3, 0x605, "movstr",	I_MIL,	REG,	3, ( R(),  R(),  RL() ) ),
	( R_2D, 0x613, "inspacc",	I_MIL,	REG,	2, ( R(),  R(), 0 ) ),
	( R_2D, 0x614, "ldphy",	I_MIL,	REG,	2, ( R(),  R(), 0 ) ),
	( R_3, 0x617, "fill",		I_MIL,	REG,	3, ( R(),  RL(), RL() ) ),
	( R_2D, 0x646, "condrec",	I_MIL,	REG,	2, ( R(),  R(), 0 ) ),
	( R_2D, 0x656, "receive",	I_MIL,	REG,	2, ( R(),  R(), 0 ) ),
	( R_3, 0x662, "send",		I_MIL,	REG,	3, ( R(),  RL(), R() ) ),
	( R_1, 0x663, "sendserv",	I_MIL,	REG,	1, ( R(), 0, 0 )	),
	( R_1, 0x664, "resumprcs",	I_MIL,	REG,	1, ( R(), 0, 0 )	),
	( R_1, 0x665, "schedprcs",	I_MIL,	REG,	1, ( R(), 0, 0 )	),
	( R_0, 0x666, "saveprcs",	I_MIL,	REG,	0, ( 0, 0, 0 )	),
	( R_1, 0x668, "condwait",	I_MIL,	REG,	1, ( R(), 0, 0 )	),
	( R_1, 0x669, "wait",		I_MIL,	REG,	1, ( R(), 0, 0 )	),
	( R_1, 0x66a, "signal",	I_MIL,	REG,	1, ( R(), 0, 0 )	),
	( R_1D, 0x673, "ldtime",	I_MIL,	REG,	1, ( R2(), 0, 0 )	),


	# /* CX extensions */

	( R_3, 0x5d8, "eshro",	I_CX2,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x630, "sdma",		I_CX,	REG,	3, ( RSL(), RSL(), RL() ) ),
	( R_3, 0x631, "udma",		I_CX,	REG,	0, ( 0, 0, 0 )	),
	( R_3, 0x659, "sysctl",	I_CX2,	REG,	3, ( RSL(), RSL(), RL() ) ),


	# /* Jx extensions.  */
	( R_3, 0x780, "addono",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x790, "addog",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7a0, "addoe",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7b0, "addoge",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7c0, "addol",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7d0, "addone",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7e0, "addole",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7f0, "addoo",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x781, "addino",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x791, "addig",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7a1, "addie",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7b1, "addige",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7c1, "addil",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7d1, "addine",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7e1, "addile",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7f1, "addio",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),

	( R_2D, 0x5ad, "bswap",	I_JX,	REG,	2, ( RSL(), RS(), 0 ) ),

	( R_2, 0x594, "cmpob",	I_JX,	REG,	2, ( RSL(), RSL(), 0 ) ),
	( R_2, 0x595, "cmpib",	I_JX,	REG,	2, ( RSL(), RSL(), 0 ) ),
	( R_2, 0x596, "cmpos",	I_JX,	REG,	2, ( RSL(), RSL(), 0 ) ),
	( R_2, 0x597, "cmpis",	I_JX,	REG,	2, ( RSL(), RSL(), 0 ) ),

	( R_3, 0x784, "selno",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x794, "selg",		I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7a4, "sele",		I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7b4, "selge",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7c4, "sell",		I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7d4, "selne",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7e4, "selle",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7f4, "selo",		I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),

	( R_3, 0x782, "subono",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x792, "subog",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7a2, "suboe",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7b2, "suboge",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7c2, "subol",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7d2, "subone",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7e2, "subole",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7f2, "suboo",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x783, "subino",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x793, "subig",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7a3, "subie",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7b3, "subige",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7c3, "subil",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7d3, "subine",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7e3, "subile",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_3, 0x7f3, "subio",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),

	( R_3, 0x65c, "dcctl",	I_JX,	REG,	3, ( RSL(), RSL(), RL() ) ),
	( R_3, 0x65b, "icctl",	I_JX,	REG,	3, ( RSL(), RSL(), RS() ) ),
	( R_2D, 0x658, "intctl",	I_JX,	REG,	2, ( RSL(), RS(), 0 ) ),
	( R_0, 0x5b4, "intdis",	I_JX,	REG,	0, (   0,  0, 0 ) ),
	( R_0, 0x5b5, "inten",	I_JX,	REG,	0, (   0,  0, 0 ) ),
	( R_0, 0x65d, "halt",		I_JX,	REG,	1, ( RSL(),  0, 0 ) ),

	# /* Hx extensions.  */
	( REG_OPC, 0xac, "dcinva",	I_HX,	MEM1,	1, (   M,  0, 0 ) ),
]

a = []
for _ in opcodes:
    opc = Opcode(_)
    a.append(opc)
a.sort()

global_tables.sort()
for _ in global_tables:
    thing = do_global(_)
    if len(thing) > 0:
        print("%s\n\n" % thing)

for _ in a:
    print("# %s\n%s\n\n" % (_.name, _))
