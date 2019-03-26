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
package ghidra.app.util.bin.format.macho;

public final class CpuSubTypes {

	/*
	 *	PowerPC subtypes
	 */
	public final static int CPU_SUBTYPE_POWERPC_ALL      = 0;
	public final static int CPU_SUBTYPE_POWERPC_601      = 1;
	public final static int CPU_SUBTYPE_POWERPC_602      = 2;
	public final static int CPU_SUBTYPE_POWERPC_603      = 3;
	public final static int CPU_SUBTYPE_POWERPC_603e     = 4;
	public final static int CPU_SUBTYPE_POWERPC_603ev    = 5;
	public final static int CPU_SUBTYPE_POWERPC_604      = 6;
	public final static int CPU_SUBTYPE_POWERPC_604e     = 7;
	public final static int CPU_SUBTYPE_POWERPC_620      = 8;
	public final static int CPU_SUBTYPE_POWERPC_750      = 9;
	public final static int CPU_SUBTYPE_POWERPC_7400     = 10;
	public final static int CPU_SUBTYPE_POWERPC_7450     = 11;
	public final static int CPU_SUBTYPE_POWERPC_Max      = 10;//open source
	public final static int CPU_SUBTYPE_POWERPC_SCVger   = 11;//open source
	public final static int CPU_SUBTYPE_POWERPC_970      = 100;

	/*
	 *	I386 subtypes
	 */
	public final static int	CPU_SUBTYPE_I386_ALL         = CPU_SUBTYPE_INTEL(3, 0);
	public final static int CPU_SUBTYPE_386              = CPU_SUBTYPE_INTEL(3, 0);
	public final static int CPU_SUBTYPE_486              = CPU_SUBTYPE_INTEL(4, 0);
	public final static int CPU_SUBTYPE_486SX            = CPU_SUBTYPE_INTEL(4, 8);// 8 << 4 = 128
	public final static int CPU_SUBTYPE_586              = CPU_SUBTYPE_INTEL(5, 0);
	public final static int CPU_SUBTYPE_PENT             = CPU_SUBTYPE_INTEL(5, 0);
	public final static int CPU_SUBTYPE_PENTPRO          = CPU_SUBTYPE_INTEL(6, 1);
	public final static int CPU_SUBTYPE_PENTII_M3        = CPU_SUBTYPE_INTEL(6, 3);
	public final static int CPU_SUBTYPE_PENTII_M5        = CPU_SUBTYPE_INTEL(6, 5);
	public final static int CPU_SUBTYPE_CELERON          = CPU_SUBTYPE_INTEL(7, 6);
	public final static int CPU_SUBTYPE_CELERON_MOBILE   = CPU_SUBTYPE_INTEL(7, 7);
	public final static int CPU_SUBTYPE_PENTIUM_3        = CPU_SUBTYPE_INTEL(8, 0);
	public final static int CPU_SUBTYPE_PENTIUM_3_M      = CPU_SUBTYPE_INTEL(8, 1);
	public final static int CPU_SUBTYPE_PENTIUM_3_XEON   = CPU_SUBTYPE_INTEL(8, 2);
	public final static int CPU_SUBTYPE_PENTIUM_M        = CPU_SUBTYPE_INTEL(9, 0);
	public final static int CPU_SUBTYPE_PENTIUM_4        = CPU_SUBTYPE_INTEL(10, 0);
	public final static int CPU_SUBTYPE_PENTIUM_4_M      = CPU_SUBTYPE_INTEL(10, 1);
	public final static int CPU_SUBTYPE_ITANIUM          = CPU_SUBTYPE_INTEL(11, 0);
	public final static int CPU_SUBTYPE_ITANIUM_2        = CPU_SUBTYPE_INTEL(11, 1);
	public final static int CPU_SUBTYPE_XEON             = CPU_SUBTYPE_INTEL(12, 0);
	public final static int CPU_SUBTYPE_XEON_MP          = CPU_SUBTYPE_INTEL(12, 1);

	private final static int CPU_SUBTYPE_INTEL(int f, int m)	{
		return f + (m << 4);
	}

	/*
	 *	X86 subtypes.
	 */
	public final static int CPU_SUBTYPE_X86_ALL          = 3;
	public final static int CPU_SUBTYPE_X86_ARCH1        = 4;

	public final static int CPU_THREADTYPE_INTEL_HTT     = 1;

	/*
	 *	Mips subtypes.
	 */
	public final static int	CPU_SUBTYPE_MIPS_ALL      = 0;
	public final static int CPU_SUBTYPE_MIPS_R2300    = 1;
	public final static int CPU_SUBTYPE_MIPS_R2600    = 2;
	public final static int CPU_SUBTYPE_MIPS_R2800    = 3;
	public final static int CPU_SUBTYPE_MIPS_R2000a   = 4;/* pmax */
	public final static int CPU_SUBTYPE_MIPS_R2000    = 5;
	public final static int CPU_SUBTYPE_MIPS_R3000a   = 6;/* 3max */
	public final static int CPU_SUBTYPE_MIPS_R3000    = 7;

	/*
	 *	MC98000 (PowerPC) subtypes
	 */
	public final static int	CPU_SUBTYPE_MC98000_ALL	= 0;
	public final static int CPU_SUBTYPE_MC98601     = 1;

	/*
	 *	HPPA subtypes for Hewlett-Packard HP-PA family of
	 *	risc processors. Port by NeXT to 700 series. 
	 */
	public final static int	CPU_SUBTYPE_HPPA_ALL        = 0;
	public final static int CPU_SUBTYPE_HPPA_7100       = 0; /* compat */
	public final static int CPU_SUBTYPE_HPPA_7100LC     = 1;

	/*
	 *	MC88000 subtypes.
	 */
	public final static int	CPU_SUBTYPE_MC88000_ALL    = 0;
	public final static int CPU_SUBTYPE_MC88100        = 1;
	public final static int CPU_SUBTYPE_MC88110        = 2;

	/*
	 *	SPARC subtypes
	 */
	public final static int	CPU_SUBTYPE_SPARC_ALL  = 0;

	/*
	 *	I860 subtypes
	 */
	public final static int CPU_SUBTYPE_I860_ALL   = 0;
	public final static int CPU_SUBTYPE_I860_860   = 1;

	/*
	 *	VAX subtypes
	 */
	public final static int	CPU_SUBTYPE_VAX_ALL	 = 0; 
	public final static int CPU_SUBTYPE_VAX780	 = 1;
	public final static int CPU_SUBTYPE_VAX785	 = 2;
	public final static int CPU_SUBTYPE_VAX750	 = 3;
	public final static int CPU_SUBTYPE_VAX730	 = 4;
	public final static int CPU_SUBTYPE_UVAXI	 = 5;
	public final static int CPU_SUBTYPE_UVAXII	 = 6;
	public final static int CPU_SUBTYPE_VAX8200	 = 7;
	public final static int CPU_SUBTYPE_VAX8500	 = 8;
	public final static int CPU_SUBTYPE_VAX8600	 = 9;
	public final static int CPU_SUBTYPE_VAX8650	 = 10;
	public final static int CPU_SUBTYPE_VAX8800	 = 11;
	public final static int CPU_SUBTYPE_UVAXIII	 = 12;

	/*
	 * 	680x0 subtypes
	 */
	public final static int	CPU_SUBTYPE_MC680x0_ALL   = 1;
	public final static int CPU_SUBTYPE_MC68030       = 1;
	public final static int CPU_SUBTYPE_MC68040       = 2; 
	public final static int	CPU_SUBTYPE_MC68030_ONLY  = 3;

	/*
	 *  ARM subtypes
	 */
	public final static int	CPU_SUBTYPE_ARM_ALL        =  0;
	public final static int	CPU_SUBTYPE_ARM_V4T        =  5;
	public final static int	CPU_SUBTYPE_ARM_V6         =  6;
	public final static int	CPU_SUBTYPE_ARM_V5         =  7;
	public final static int	CPU_SUBTYPE_ARM_V5TEJ      =  7;
	public final static int	CPU_SUBTYPE_ARM_XSCALE     =  8;
	public final static int	CPU_SUBTYPE_ARM_V7         =  9;
	public final static int	CPU_SUBTYPE_ARM_V7F        = 10;//unused
	public final static int	CPU_SUBTYPE_ARM_V7S        = 11;
	public final static int	CPU_SUBTYPE_ARM_V7K        = 12;
	public final static int	CPU_SUBTYPE_ARM_V6M        = 14;
	public final static int	CPU_SUBTYPE_ARM_V7M        = 15;
	public final static int	CPU_SUBTYPE_ARM_V7EM       = 16;

	public final static int CPU_SUBTYPE_MULTIPLE       = -1;
	public final static int CPU_SUBTYPE_LITTLE_ENDIAN  =  0;
	public final static int CPU_SUBTYPE_BIG_ENDIAN     =  1;

}
