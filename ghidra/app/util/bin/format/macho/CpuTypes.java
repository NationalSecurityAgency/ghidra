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

import ghidra.program.model.lang.*;

public final class CpuTypes {

	/** mask for architecture bits */
	public final static int CPU_ARCH_MASK    = 0xff000000;

	/** 64 bit ABI */
	public final static int CPU_ARCH_ABI64   = 0x01000000;

	public final static int CPU_TYPE_ANY        = -1;
	public final static int CPU_TYPE_VAX        = 0x1;
	// UNUSED                                     0x2
	// UNUSED                                     0x3
	// UNUSED                                     0x4
	// UNUSED                                     0x5
	public final static int CPU_TYPE_MC680x0    = 0x6;
	public final static int CPU_TYPE_X86        = 0x7;
	public final static int CPU_TYPE_I386       = CPU_TYPE_X86;		/* compatibility */
	// CPU_TYPE_MIPS                              0x8 
	// UNUSED                                     0x9
	public final static int CPU_TYPE_MC98000    = 0xa;
	public final static int CPU_TYPE_HPPA       = 0xb;
	public final static int CPU_TYPE_ARM        = 0xc;
	public final static int CPU_TYPE_MC88000    = 0xd;
	public final static int CPU_TYPE_SPARC      = 0xe;
	public final static int CPU_TYPE_I860       = 0xf;
	// CPU_TYPE_ALPHA                             0x10
	// UNUSED                                     0x11
	public final static int CPU_TYPE_POWERPC    = 0x12;

	public final static int CPU_TYPE_POWERPC64  = (CPU_TYPE_POWERPC | CPU_ARCH_ABI64);
	public final static int CPU_TYPE_X86_64     = (CPU_TYPE_X86     | CPU_ARCH_ABI64);
	public final static int CPU_TYPE_ARM_64     = (CPU_TYPE_ARM     | CPU_ARCH_ABI64);


	/**
	 * Returns the processor name of the given CPU type value.
	 * @param cpuType the CPU type value
	 * @param cpuSubtype the CPU subtype value
	 * @return the processor name of the given CPU type value
	 */
	public final static Processor getProcessor(int cpuType, int cpuSubtype) {
		switch (cpuType) {
			case CPU_TYPE_X86:        
				return Processor.findOrPossiblyCreateProcessor("x86");
			case CPU_TYPE_X86_64:     
				return Processor.findOrPossiblyCreateProcessor("x86");
			case CPU_TYPE_POWERPC:    
				return Processor.findOrPossiblyCreateProcessor("PowerPC");
			case CPU_TYPE_POWERPC64:  
				return Processor.findOrPossiblyCreateProcessor("PowerPC");
			case CPU_TYPE_I860:       
				return Processor.findOrPossiblyCreateProcessor("i860");
			case CPU_TYPE_SPARC:      
				return Processor.findOrPossiblyCreateProcessor("Sparc");
			case CPU_TYPE_ARM:        
				return Processor.findOrPossiblyCreateProcessor("ARM");
			case CPU_TYPE_ARM_64:        
				return Processor.findOrPossiblyCreateProcessor("AARCH64");
		}
		throw new RuntimeException("Unrecognized CPU type: 0x"+Integer.toHexString(cpuType));
	}

	public final static int getProcessorBitSize(int cpuType) {
		switch (cpuType) {
			case CPU_TYPE_ARM:
			case CPU_TYPE_SPARC:
			case CPU_TYPE_I860:
			case CPU_TYPE_POWERPC:
			case CPU_TYPE_X86:       return 32;

			case CPU_TYPE_ARM_64:
			case CPU_TYPE_POWERPC64:
			case CPU_TYPE_X86_64:    return 64;
		}
		throw new RuntimeException("Unrecognized CPU type: 0x"+Integer.toHexString(cpuType));
	}

	public static String getMagicString(int cpuType, int cpuSubtype) {
		switch (cpuType) {
			case CPU_TYPE_ARM:        
				return ""+cpuType+"."+cpuSubtype;
		}
		return ""+cpuType;
	}
	
}
