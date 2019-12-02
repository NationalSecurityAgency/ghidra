/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf;

/**
 * A collection of constants used in the ELF header.
 */
public interface ElfConstants {

	// ELF Identification Area Indexes

	/**Length of the File ID*/
	public static final int EI_NIDENT = 16;
	/** File ID*/
	public static final int EI_MAG0 = 0;
	/**File ID*/
	public static final int EI_MAG1 = 1;
	/**File ID*/
	public static final int EI_MAG2 = 2;
	/**File ID*/
	public static final int EI_MAG3 = 3;
	/**File class*/
	public static final int EI_CLASS = 4;
	/**Data encoding*/
	public static final int EI_DATA = 5;
	/**File version*/
	public static final int EI_VERSION = 6;
	/**Operating System/ABI Identification*/
	public static final int EI_OSIABI = 7;
	/**ABI Version*/
	public static final int EI_ABIVERSION = 8;
	/**Start of padding*/
	public static final int EI_PAD = 9;

	//ABI - application binary interface

	// ELF Identification - File identification values

	/**The ELF magic number*/
	public static final byte MAGIC_NUM = 0x7f;
	/**The ELF magic string*/
	public static final String MAGIC_STR = "ELF";
	/**The ELF magic number and string as a byte array*/
	public static final byte[] MAGIC_BYTES = { 0x7f, 'E', 'L', 'F' };
	/**The ELF magic string length*/
	public static final int MAGIC_STR_LEN = 3;

	// ELF Identification - File class values

	/**Invalid class*/
	public static final byte ELF_CLASS_NONE = 0;
	/**{@code 32-bit objects}*/
	public static final byte ELF_CLASS_32 = 1;
	/**{@code 64-bit objects}*/
	public static final byte ELF_CLASS_64 = 2;
	/**?*/
	public static final byte ELF_CLASS_NUM = 3;

	// ELF Identification - Data encoding values

	/**invalid byte order*/
	public static final byte ELF_DATA_NONE = 0;
	/**little-endian byte order*/
	public static final byte ELF_DATA_LE = 1;
	/**big-endian byte order*/
	public static final byte ELF_DATA_BE = 2;

	// ELF Identification - File version values

	/**invalid version*/
	public static final byte EV_NONE = 0;
	/**current version*/
	public static final byte EV_CURRENT = 1;

	// ELF Identification - OS/ABI values

	/**no extension or unspecified*/
	public static final byte ELFOSABI_NONE = 0;
	/**hewlett packard unix*/
	public static final byte ELFOSABI_HPUX = 1;
	/**net bsd*/
	public static final byte ELFOSABI_NETBSD = 2;
	/**linux*/
	public static final byte ELFOSABI_LINUX = 3;
	/** GNU LINUX */
	public static final byte ELFOSABI_GNU = 3;
	/** GNU/Hurd */
	public static final byte ELFOSABI_HURD = 4;
	/**sun solaris*/
	public static final byte ELFOSABI_SOLARIS = 6;
	/**aix*/
	public static final byte ELFOSABI_AIX = 7;
	/**irix*/
	public static final byte ELFOSABI_IRIX = 8;
	/**free bsd*/
	public static final byte ELFOSABI_FREEBSD = 9;
	/**{@code compaq tru64 unix}*/
	public static final byte ELFOSABI_TRUE64 = 10;
	/**novell modesto*/
	public static final byte ELFOSABI_MODESTO = 11;
	/**open bsd*/
	public static final byte ELFOSABI_OPENBSD = 12;
	/** OpenVMS */
	public static final byte ELFOSABI_OPENVMS = 13;
	/** Hewlett-Packard Non-Stop Kernel */
	public static final byte ELFOSABI_NSK = 14;
	/** AROS */
	public static final byte ELFOSABI_AROS = 15;
	/** FenixOS */
	public static final byte ELFOSABI_FENIXOS = 16;
	/**{@code Bare-metal TMS320C6000}*/
	public static final byte ELFOSABI_C6000_ELFABI = 64;
	/**{@code Linux TMS320C6000}*/
	public static final byte ELFOSABI_C6000_LINUX = 65;
	/** ARM */
	public static final byte ELFOSABI_ARM = 97;
	/** Standalone (embedded) application */
	public static final byte ELFOSABI_STANDALONE = (byte) 255;

	//values 64-255, architecture-specific value range 

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// File Types

	/**No file type*/
	public static final short ET_NONE = 0;
	/**Relocatable file (suitable for linking)*/
	public static final short ET_REL = 1;
	/**Executable file*/
	public static final short ET_EXEC = 2;
	/**Shared object file*/
	public static final short ET_DYN = 3;
	/**Core file*/
	public static final short ET_CORE = 4;
	/**Processor specific*/
	public static final short ET_LOPROC = (short) 0xff00;
	/**Processor specific*/
	public static final short ET_HIPROC = (short) 0xffff;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	// Machines

	/**No machine*/
	public static final short EM_NONE = 0;
	/**{@code AT&T WE 32100}*/
	public static final short EM_M32 = 1;
	/**SUN SPARC */
	public static final short EM_SPARC = 2;
	/**{@code Intel 80386}*/
	public static final short EM_386 = 3;
	/**{@code Motorola m68k family}*/
	public static final short EM_68K = 4;
	/**{@code Motorola m88k family}*/
	public static final short EM_88K = 5;
	/**{@code Intel 486 (deprecated)}*/
	public static final short EM_486 = 6;
	/**{@code Intel 80860}*/
	public static final short EM_860 = 7;
	/**{@code MIPS R3000 big-endian}*/
	public static final short EM_MIPS = 8;
	/**{@code IBM System/370}*/
	public static final short EM_S370 = 9;
	/**{@code MIPS R3000 little-endian}*/
	public static final short EM_MIPS_RS3_LE = 10;
	// 11 - 14 reserved
	/**HPPA */
	public static final short EM_PARISC = 15;
	/**{@code Fujitsu VPP500}*/
	public static final short EM_VPP500 = 17;
	/**{@code Sun's "v8plus"}*/
	public static final short EM_SPARC32PLUS = 18;
	/**{@code Intel 80960}*/
	public static final short EM_960 = 19;
	/**PowerPC */
	public static final short EM_PPC = 20;
	/**{@code PowerPC 64-bit}*/
	public static final short EM_PPC64 = 21;
	/**{@code IBM S390}*/
	public static final short EM_S390 = 22;
	//23 - 35  reserved
	/**{@code NEC V800 series}*/
	public static final short EM_V800 = 36;
	/**{@code Fujitsu FR20}*/
	public static final short EM_FR20 = 37;
	/**{@code TRW RH-32}*/
	public static final short EM_RH32 = 38;
	/**Motorola RCE */
	public static final short EM_RCE = 39;
	/**ARM */
	public static final short EM_ARM = 40;
	/**Digital Alpha */
	public static final short EM_FAKE_ALPHA = 41;
	/**Hitachi SH */
	public static final short EM_SH = 42;
	/**{@code SPARC v9 64-bit}*/
	public static final short EM_SPARCV9 = 43;
	/**Siemens Tricore */
	public static final short EM_TRICORE = 44;
	/**Argonaut RISC Core */
	public static final short EM_ARC = 45;
	/**{@code Hitachi H8/300}*/
	public static final short EM_H8_300 = 46;
	/**{@code Hitachi H8/300H}*/
	public static final short EM_H8_300H = 47;
	/**{@code Hitachi H8S}*/
	public static final short EM_H8S = 48;
	/**{@code Hitachi H8/500}*/
	public static final short EM_H8_500 = 49;
	/** Intel Merced */
	public static final short EM_IA_64 = 50;
	/** Stanford MIPS-X */
	public static final short EM_MIPS_X = 51;
	/** Motorola Coldfire */
	public static final short EM_COLDFIRE = 52;
	/**{@code Motorola M68HC12}*/
	public static final short EM_68HC12 = 53;
	/** Fujitsu MMA Multimedia Accelerator*/
	public static final short EM_MMA = 54;
	/** Siemens PCP */
	public static final short EM_PCP = 55;
	/** Sony nCPU embedded RISC */
	public static final short EM_NCPU = 56;
	/**{@code Denso NDR1 microprocessor}*/
	public static final short EM_NDR1 = 57;
	/** Motorola Start*Core processor */
	public static final short EM_STARCORE = 58;
	/**{@code  Toyota ME16 processor}*/
	public static final short EM_ME16 = 59;
	/**{@code STMicroelectronic ST100 processor}*/
	public static final short EM_ST100 = 60;
	/** Advanced Logic Corp. Tinyj emb.fam*/
	public static final short EM_TINYJ = 61;
	/**{@code AMD x86-64 architecture}*/
	public static final short EM_X86_64 = 62;
	/** Sony DSP Processor */
	public static final short EM_PDSP = 63;
	// 64 reserved
	// 65 reserved
	/**{@code  Siemens FX66 microcontroller}*/
	public static final short EM_FX66 = 66;
	/**{@code STMicroelectronics ST9+ 8/16 mc}*/
	public static final short EM_ST9PLUS = 67;
	/**{@code STmicroelectronics ST7 8 bit mc}*/
	public static final short EM_ST7 = 68;
	/**{@code  Motorola MC68HC16 microcontroller}*/
	public static final short EM_68HC16 = 69;
	/**{@code  Motorola MC68HC11 microcontroller}*/
	public static final short EM_68HC11 = 70;
	/**{@code  Motorola MC68HC08 microcontroller}*/
	public static final short EM_68HC08 = 71;
	/**{@code  Motorola MC68HC05 microcontroller}*/
	public static final short EM_68HC05 = 72;
	/** Silicon Graphics SVx */
	public static final short EM_SVX = 73;
	/**{@code STMicroelectronics ST19 8 bit mc}*/
	public static final short EM_ST19 = 74;
	/** Digital VAX */
	public static final short EM_VAX = 75;
	/**{@code Axis Communications 32-bit embedded processor}*/
	public static final short EM_CRIS = 76;
	/**{@code Infineon Technologies 32-bit embedded processor}*/
	public static final short EM_JAVELIN = 77;
	/**{@code Element 14 64-bit DSP Processor}*/
	public static final short EM_FIREPATH = 78;
	/**{@code LSI Logic 16-bit DSP Processor}*/
	public static final short EM_ZSP = 79;
	/**{@code Donald Knuth's educational 64-bit processor}*/
	public static final short EM_MMIX = 80;
	/** Harvard University machine-independent object files */
	public static final short EM_HUANY = 81;
	/** SiTera Prism */
	public static final short EM_PRISM = 82;
	/**{@code Atmel AVR 8-bit microcontroller}*/
	public static final short EM_AVR = 83;
	/**{@code Fujitsu FR30}*/
	public static final short EM_FR30 = 84;
	/**{@code Mitsubishi D10V}*/
	public static final short EM_D10V = 85;
	/**{@code Mitsubishi D30V}*/
	public static final short EM_D30V = 86;
	/**{@code NEC v850}*/
	public static final short EM_V850 = 87;
	/**{@code Mitsubishi M32R}*/
	public static final short EM_M32R = 88;
	/**{@code Matsushita MN10300}*/
	public static final short EM_MN10300 = 89;
	/**{@code Matsushita MN10200}*/
	public static final short EM_MN10200 = 90;
	/** picoJava */
	public static final short EM_PJ = 91;
	/**{@code  OpenRISC 32-bit embedded processor}*/
	public static final short EM_OPENRISC = 92;
	/**{@code  ARC Cores Tangent-A5}*/
	public static final short EM_ARC_A5 = 93;
	/** Tensilica Xtensa Architecture */
	public static final short EM_XTENSA = 94;
	/** Alphamosaic VideoCore processor*/
	public static final short EM_VIDEOCORE = 95;
	/** Thompson Multimedia General Purpose Processor*/
	public static final short EM_TMM_GPP = 96;
	/**{@code  National Semiconductor 32000 series}*/
	public static final short EM_NS32K = 97;
	/** Tenor Network TPC processor */
	public static final short EM_TPC = 98;
	/**{@code  Trebia SNP 1000 processor}*/
	public static final short EM_SNP1K = 99;
	/**{@code  STMicroelectronics (www.st.com) ST200}*/
	public static final short EM_ST200 = 100;
	/**{@code  Ubicom IP2xxx microcontroller family}*/
	public static final short EM_IP2K = 101;
	/** MAX Processor */
	public static final short EM_MAX = 102;
	/** National Semiconductor CompactRISC microprocessor */
	public static final short EM_CR = 103;
	/**{@code  Fujitsu F2MC16}*/
	public static final short EM_F2MC16 = 104;
	/**{@code  Texas Instruments embedded microcontroller msp430}*/
	public static final short EM_MSP430 = 105;
	/** Analog Devices Blackfin (DSP) processor */
	public static final short EM_BLACKFIN = 106;
	/**{@code  S1C33 Family of Seiko Epson processors}*/
	public static final short EM_SE_C33 = 107;
	/** Sharp embedded microprocessor */
	public static final short EM_SEP = 108;
	/** Arca RISC Microprocessor */
	public static final short EM_ARCA = 109;
	/** Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University */
	public static final short EM_UNICORE = 110;
	/**{@code  eXcess: 16/32/64-bit configurable embedded CPU}*/
	public static final short EM_EXCESS = 111;
	/** Icera Semiconductor Inc. Deep Execution Processor */
	public static final short EM_DXP = 112;
	/** Altera Nios II soft-core processor */
	public static final short EM_ALTERA_NIOS2 = 113;
	/** National Semiconductor CompactRISC CRX */
	public static final short EM_CRX = 114;
	/** Motorola XGATE embedded processor */
	public static final short EM_XGATE = 115;
	/**{@code  Infineon C16x/XC16x processor}*/
	public static final short EM_C166 = 116;
	/**{@code  Renesas M16C series microprocessors}*/
	public static final short EM_M16C = 117;
	/**{@code  Microchip Technology dsPIC30F Digital Signal Controller}*/
	public static final short EM_DSPIC30F = 118;
	/** Freescale Communication Engine RISC core */
	public static final short EM_CE = 119;
	/**{@code  Renesas M32C series microprocessors*}*/
	public static final short EM_M32C = 120;
	/**{@code  Altium TSK3000 core}*/
	public static final short EM_TSK3000 = 131;
	/**{@code  Freescale RS08 embedded processor}*/
	public static final short EM_RS08 = 132;
	/**{@code  Analog Devices SHARC family of 32-bit DSP processors}*/
	public static final short EM_SHARC = 133;
	/**{@code  Cyan Technology eCOG2 microprocessor}*/
	public static final short EM_ECOG2 = 134;
	/**{@code  Sunplus S+core7 RISC processor}*/
	public static final short EM_SCORE7 = 135;
	/**{@code  New Japan Radio (NJR) 24-bit DSP Processor}*/
	public static final short EM_DSP24 = 136;
	/** Broadcom VideoCore III processor */
	public static final short EM_VIDEOCORE3 = 137;
	/** RISC processor for Lattice FPGA architecture */
	public static final short EM_LATTICEMICO32 = 138;
	/**{@code  Seiko Epson C17 family}*/
	public static final short EM_SE_C17 = 139;
	/**{@code  The Texas Instruments TMS320C6000 DSP family}*/
	public static final short EM_TI_C6000 = 140;
	/**{@code  The Texas Instruments TMS320C2000 DSP family}*/
	public static final short EM_TI_C2000 = 141;
	/**{@code  The Texas Instruments TMS320C55x DSP family}*/
	public static final short EM_TI_C5500 = 142;
	/**{@code  STMicroelectronics 64bit VLIW Data Signal Processor}*/
	public static final short EM_MMDSP_PLUS = 160;
	/**{@code  Cypress M8C microprocessor}*/
	public static final short EM_CYPRESS_M8C = 161;
	/**{@code  Renesas R32C series microprocessors}*/
	public static final short EM_R32C = 162;
	/** NXP Semiconductors TriMedia architecture family */
	public static final short EM_TRIMEDIA = 163;
	/** Qualcomm Hexagon processor */
	public static final short EM_HEXAGON = 164;
	/**{@code  Intel 8051 and variants}*/
	public static final short EM_8051 = 165;
	/**{@code  STMicroelectronics STxP7x family of RISC processors}*/
	public static final short EM_STXP7X = 166;
	/** Andes Technology compact code size embedded RISC processor family */
	public static final short EM_NDS32 = 167;
	/**{@code  Cyan Technology eCOG1X family}*/
	public static final short EM_ECOG1 = 168;
	/**{@code  Cyan Technology eCOG1X family}*/
	public static final short EM_ECOG1X = 168;
	/**{@code  Dallas Semiconductor MAXQ30 Core Micro-controllers}*/
	public static final short EM_MAXQ30 = 169;
	/**{@code  New Japan Radio (NJR) 16-bit DSP Processor}*/
	public static final short EM_XIMO16 = 170;
	/**{@code  M2000 Reconfigurable RISC Microprocessor}*/
	public static final short EM_MANIK = 171;
	/**{@code  Cray Inc. NV2 vector architecture}*/
	public static final short EM_CRAYNV2 = 172;
	/** Renesas RX family */
	public static final short EM_RX = 173;
	/** Imagination Technologies META processor architecture */
	public static final short EM_METAG = 174;
	/** MCST Elbrus general purpose hardware architecture */
	public static final short EM_MCST_ELBRUS = 175;
	/**{@code  Cyan Technology eCOG16 family}*/
	public static final short EM_ECOG16 = 176;
	/**{@code  National Semiconductor CompactRISC CR16 16-bitmicroprocessor}*/
	public static final short EM_CR16 = 177;
	/** Freescale Extended Time Processing Unit */
	public static final short EM_ETPU = 178;
	/**{@code  Infineon Technologies SLE9X core}*/
	public static final short EM_SLE9X = 179;
	/**{@code  Intel L10M}*/
	public static final short EM_L10M = 180;
	/**{@code  Intel K10M}*/
	public static final short EM_K10M = 181;
	// 182 reserved
	/**{@code  AARCH64 Architecture}*/
	public static final short EM_AARCH64 = 183;
	/**{@code  Atmel Corporation 32-bit microprocessor family}*/
	public static final short EM_AVR32 = 185;
	/**{@code  STMicroeletronics STM8 8-bit microcontroller}*/
	public static final short EM_STM8 = 186;
	/**{@code  Tilera TILE64 multicore architecture family}*/
	public static final short EM_TILE64 = 187;
	/** Tilera TILEPro multicore architecture family */
	public static final short EM_TILEPRO = 188;
	/** NVIDIA CUDA architecture */
	public static final short EM_CUDA = 190;
	/** Tilera TILE-Gx multicore architecture family */
	public static final short EM_TILEGX = 191;
	/** CloudShield architecture family */
	public static final short EM_CLOUDSHIELD = 192;
	/**{@code  KIPO-KAIST Core-A 1st generation processor family}*/
	public static final short EM_COREA_1ST = 193;
	/**{@code  KIPO-KAIST Core-A 2nd generation processor family}*/
	public static final short EM_COREA_2ND = 194;
	/**{@code  Synopsys ARCompact V2}*/
	public static final short EM_ARC_COMPACT2 = 195;
	/**{@code  Open8 8-bit RISC soft processor core}*/
	public static final short EM_OPEN8 = 196;
	/**{@code  Renesas RL78 family}*/
	public static final short EM_RL78 = 197;
	/** Broadcom VideoCore V processor */
	public static final short EM_VIDEOCORE5 = 198;
	/**{@code  Renesas 78KOR family}*/
	public static final short EM_78KOR = 199;
	/**{@code  Freescale 56800EX Digital Signal Controller (DSC)}*/
	public static final short EM_56800EX = 200;
	/**{@code  Beyond BA1 CPU}*/
	public static final short EM_BA1 = 201;
	/**{@code  Beyond BA2 CPU}*/
	public static final short EM_BA2 = 202;
	/** XMOS xCORE processor family */
	public static final short EM_XCORE = 203;
	/**{@code  KM211 KM32 32-bit processor}*/
	public static final short EM_KM32 = 210;
	/**{@code  KM211 KMX32 32-bit processor}*/
	public static final short EM_KMX32 = 211;
	/**{@code  KM211 KMX16 16-bit processor}*/
	public static final short EM_KMX16 = 212;
	/**{@code  KM211 KMX8 8-bit processor}*/
	public static final short EM_KMX8 = 213;
	/**{@code  KM211 KVARC processor}*/
	public static final short EM_KVARC = 214;
	/** Paneve CDP architecture family */
	public static final short EM_CDP = 215;
	/** Cognitive Smart Memory Processor */
	public static final short EM_COGE = 216;
	/** iCelero CoolEngine */
	public static final short EM_COOL = 217;
	/** Nanoradio Optimized RISC */
	public static final short EM_NORC = 218;
	/** CSR Kalimba architecture family */
	public static final short EM_CSR_KALIMBA = 219;
	/** AMD GPU architecture */
	public static final short EM_AMDGPU = 224;
	/** RISC-V */
	public static final short EM_RISCV = 243;
	/**{@code  Lanai 32-bit processor}*/
	public static final short EM_LANAI = 244;
	/** Linux kernel bpf virtual machine */
	public static final short EM_BPF = 247;

	/**{@code  used by NetBSD/avr32 - AVR 32-bit}*/
	public static final short EM_AVR32_unofficial = 0x18ad;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * The size in bytes of the entry in the program
	 * location table (PLT).
	 */
	public static final int PLT_ENTRY_SIZE = 0x10;

	/**
	 * The size in bytes of the entry in the program
	 * location table (PLT) in ARM files.
	 */
	//public static final int PLT_ENTRY_SIZE_ARM = 0x12;

}
