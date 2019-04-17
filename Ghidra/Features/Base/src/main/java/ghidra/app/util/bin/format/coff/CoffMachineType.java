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
package ghidra.app.util.bin.format.coff;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

/**
 * The Machine field has one of the following values that specifies its CPU type. 
 * An image file can be run only on the specified machine or on a system that emulates
 * the specified machine.
 */
public class CoffMachineType {

	// TODO: Need to confirm these 2 TI values are correct.  TI datasheet doesn't mention them.
	public final static short TICOFF1MAGIC = 0x00c1;
	public final static short TICOFF2MAGIC = 0x00c2;

	/**
	 * The contents of this field are assumed to be applicable to any machine type
	 */
	public final static short IMAGE_FILE_MACHINE_UNKNOWN = 0x0000;

	/**
	 * Alpha
	 */
	public final static short IMAGE_FILE_MACHINE_ALPHA = 0x0184;

	/**
	 * Alpha 64
	 */
	public final static short IMAGE_FILE_MACHINE_ALPHA64 = 0x0284;

	/**
	 * Matsushita AM33
	 */
	public final static short IMAGE_FILE_MACHINE_AM33 = 0x01d3;

	/**
	 * x64
	 */
	public final static short IMAGE_FILE_MACHINE_AMD64 = (short) 0x8664;

	/**
	 * AMD Am29000 big endian
	 */
	public final static short IMAGE_FILE_MACHINE_AM29KBIGMAGIC = 0x017a;

	/**
	 * AMD Am29000 little endian
	 */
	public final static short IMAGE_FILE_MACHINE_AM29KLITTLEMAGIC = 0x017b;

	/**
	 * ARM little endian
	 */
	public final static short IMAGE_FILE_MACHINE_ARM = 0x01c0;

	/**
	 * ARM64 little endian
	 */
	public final static short IMAGE_FILE_MACHINE_ARM64 = (short) 0xaa64;

	/**
	 * ARM Thumb-2 little endian
	 */
	public final static short IMAGE_FILE_MACHINE_ARMNT = 0x01c4;

	/**
	 * EFI byte code
	 */
	public final static short IMAGE_FILE_MACHINE_EBC = 0x0ebc;

	/**
	 * Intel 386 or later processors and compatible processors
	 */
	public final static short IMAGE_FILE_MACHINE_I386 = 0x014c;

	/**
	 * Intel 386 or later processors and compatible processors (PTX)
	 */
	public final static short IMAGE_FILE_MACHINE_I386_PTX = 0x0154;

	/**
	 * Intel 386 or later processors and compatible processors (AIX)
	 */
	public final static short IMAGE_FILE_MACHINE_I386_AIX = 0x0175;

	/**
	 * Intel i960 with read-only text segment
	 */
	public final static short IMAGE_FILE_MACHINE_I960ROMAGIC = 0x0160;

	/**
	 * Intel i960 with read-write text segment
	 */
	public final static short IMAGE_FILE_MACHINE_I960RWMAGIC = 0x0161;

	/**
	 * Intel Itanium processor family
	 */
	public final static short IMAGE_FILE_MACHINE_IA64 = 0x0200;

	/**
	 * Mitsubishi M32R little endian
	 */
	public final static short IMAGE_FILE_MACHINE_M32R = (short) 0x9041;

	/**
	 * MIPS16
	 */
	public final static short IMAGE_FILE_MACHINE_MIPS16 = 0x0266;

	/**
	 * MIPS with FPU
	 */
	public final static short IMAGE_FILE_MACHINE_MIPSFPU = 0x0366;

	/**
	 * MIPS16 with FPU
	 */
	public final static short IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466;

	/**
	 * Motorola 68000
	 */
	public final static short IMAGE_FILE_MACHINE_M68KMAGIC = 0x0268;

	/**
	 * PIC-30 (dsPIC30F)
	 */
	public final static short IMAGE_FILE_MACHINE_PIC30 = 0x1236;

	/**
	 * Power PC little endian
	 */
	public final static short IMAGE_FILE_MACHINE_POWERPC = 0x01f0;

	/**
	 * Power PC with floating point support
	 */
	public final static short IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1;

	/**
	 * MIPS little endian
	 */
	public final static short IMAGE_FILE_MACHINE_R3000 = 0x0162;

	/**
	 * MIPS little endian
	 */
	public final static short IMAGE_FILE_MACHINE_R4000 = 0x0166;

	/**
	 * MIPS little endian
	 */
	public final static short IMAGE_FILE_MACHINE_R10000 = 0x0168;

	/**
	 * RISC-V 32-bit address space
	 */
	public final static short IMAGE_FILE_MACHINE_RISCV32 = 0x5032;

	/**
	 * RISC-V 64-bit address space
	 */
	public final static short IMAGE_FILE_MACHINE_RISCV64 = 0x5064;

	/**
	 * RISC-V 128-bit address space
	 */
	public final static short IMAGE_FILE_MACHINE_RISCV128 = 0x5128;

	/**
	 * Hitachi SH3
	 */
	public final static short IMAGE_FILE_MACHINE_SH3 = 0x01a2;

	/**
	 * Hitachi SH3 DSP
	 */
	public final static short IMAGE_FILE_MACHINE_SH3DSP = 0x01a3;

	/**
	 * Hitachi SH4
	 */
	public final static short IMAGE_FILE_MACHINE_SH4 = 0x01a6;

	/**
	 * Hitachi SH5
	 */
	public final static short IMAGE_FILE_MACHINE_SH5 = 0x01a8;

	/**
	 * Texas Instruments TMS470
	 */
	public final static short IMAGE_FILE_MACHINE_TI_TMS470 = 0x0097;

	/**
	 * Texas Instruments TMS320C5400
	 */
	public final static short IMAGE_FILE_MACHINE_TI_TMS320C5400 = 0x0098;

	/**
	 * Texas Instruments TMS320C6000
	 */
	public final static short IMAGE_FILE_MACHINE_TI_TMS320C6000 = 0x0099;

	/**
	 * Texas Instruments TMS320C5500
	 */
	public final static short IMAGE_FILE_MACHINE_TI_TMS320C5500 = 0x009c;

	/**
	 * Texas Instruments TMS320C2800
	 */
	public final static short IMAGE_FILE_MACHINE_TI_TMS320C2800 = 0x009d;

	/**
	 * Texas Instruments MSP430
	 */
	public final static short IMAGE_FILE_MACHINE_TI_MSP430 = 0x00a0;

	/**
	 * Texas Instruments TMS320C5500+
	 */
	public final static short IMAGE_FILE_MACHINE_TI_TMS320C5500_PLUS = 0x00a1;

	/**
	 * Thumb
	 */
	public final static short IMAGE_FILE_MACHINE_THUMB = 0x01c2;

	/**
	 * MIPS little-endian WCE v2
	 */
	public final static short IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169;

	/**
	 * Checks to see if the given machine type is defined in this file.
	 * 
	 * @param type The machine type to check.
	 * @return True if the given machine type is defined in this file; otherwise, false.
	 */
	public static boolean isMachineTypeDefined(short type) {
		if (type == IMAGE_FILE_MACHINE_UNKNOWN) {
			// This machine type is only defined in this file for completeness.
			// We want to treat this type as an unsupported machine.
			return false;
		}

		for (Field field : CoffMachineType.class.getDeclaredFields()) {
			if (!field.isSynthetic()) {
				int modifiers = field.getModifiers();
				if (Modifier.isFinal(modifiers) && Modifier.isStatic(modifiers)) {
					try {
						if (field.getShort(null) == type) {
							return true;
						}
					}
					catch (IllegalAccessException e) {
						continue;
					}
				}
			}
		}
		return false;
	}
}
