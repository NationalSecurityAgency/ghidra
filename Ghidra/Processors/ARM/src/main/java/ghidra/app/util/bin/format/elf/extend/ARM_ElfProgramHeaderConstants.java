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
package ghidra.app.util.bin.format.elf.extend;

public class ARM_ElfProgramHeaderConstants {

	////////////////////////////////////////////////////////////////////////////////

	/** Masks bits describing the format of data in subsequent words. The masked value is described in Table 5-3, below. */
	public static final int PT_ARM_ARCHEXT_FMTMSK   =  0xff000000;
	/** Masks bits describing the architecture profile required by the executable. The masked value is described in Table 5-4, below. */
	public static final int PT_ARM_ARCHEXT_PROFMSK  =  0x00ff0000;
	/** Masks bits describing the base architecture required by the executable. The masked value is described in Table 5-5, below. */
	public static final int PT_ARM_ARCHEXT_ARCHMSK  =  0x000000ff;

	////////////////////////////////////////////////////////////////////////////////

	// Table 5-3, Architecture compatibility data formats lists the architecture 
	// compatibility data formats defined by this ABI. All other format 
	// identifiers are reserved to future revisions of this specification.

	/** There are no additional words of data. However, if EF_OSABI is non-zero, the relevant platform ABI may define additional data that follows the initial word. */
	public static final int PT_ARM_ARCHEXT_FMT_OS    =  0x00000000;
	/** 5.2.1.1, below describes the format of the following data words. */
	public static final int PT_ARM_ARCHEXT_FMT_ABI   =  0x01000000;

	////////////////////////////////////////////////////////////////////////////////

	// Table 5-4, Architecture profile compatibility data.
	// Lists the values specifying the architectural profile needed by an executable file.

	/** The architecture has no profile variants, or the image has no profile-specific constraints */
	public static final int PT_ARM_ARCHEXT_PROF_NONE       =  0x0;
	/** The executable file requires the Application profile */
	public static final int PT_ARM_ARCHEXT_PROF_ARM       =  'A' << 16;
	/** The executable file requires the Real-Time profile */
	public static final int PT_ARM_ARCHEXT_PROF_RT        =  'R' << 16;
	/** The executable file requires the Microcontroller profile */
	public static final int PT_ARM_ARCHEXT_PROF_MC        =  'M' << 16;
	/** The executable file requires the 'classic' ('A' or 'R' profile) exception model. */
	public static final int PT_ARM_ARCHEXT_PROF_CLASSIC   =  'S' << 16;

	////////////////////////////////////////////////////////////////////////////////

	//Table 5-5, Architecture version compatibility data defines the values that 
	//specify the minimum architecture version needed by this executable file. 
	//These values are identical to those of the Tag_CPU_arch attribute used 
	//in the attributes section of a relocatable file.

	/** The needed architecture is unknown or specified in some other way */
	public static final int PT_ARM_ARCHEXT_ARCH_UNKN    = 0x00;
	/** Architecture v4 */
	public static final int PT_ARM_ARCHEXT_ARCHv4       = 0x01;
	/** Architecture v4T */
	public static final int PT_ARM_ARCHEXT_ARCHv4T      = 0x02;
	/** Architecture v5T */
	public static final int PT_ARM_ARCHEXT_ARCHv5T      = 0x03;
	/** Architecture v5TE */
	public static final int PT_ARM_ARCHEXT_ARCHv5TE     = 0x04;
	/** Architecture v5TEJ */
	public static final int PT_ARM_ARCHEXT_ARCHv5TEJ    = 0x05;
	/** Architecture v6 */
	public static final int PT_ARM_ARCHEXT_ARCHv6       = 0x06;
	/** Architecture v6KZ */
	public static final int PT_ARM_ARCHEXT_ARCHv6KZ     = 0x07;
	/** Architecture v6T2 */
	public static final int PT_ARM_ARCHEXT_ARCHv6T2     = 0x08;
	/** Architecture v6K */
	public static final int PT_ARM_ARCHEXT_ARCHv6K      = 0x09;
	/** Architecture v7 (in this case the architecture profile may also be required to fully specify the needed execution environment) */
	public static final int PT_ARM_ARCHEXT_ARCHv7       = 0x0A;
	/** Architecture v6M (e.g. Cortex M0) */
	public static final int PT_ARM_ARCHEXT_ARCHv6M      = 0x0B;
	/** Architecture v6S-M (e.g. Cortex M0) */
	public static final int PT_ARM_ARCHEXT_ARCHv6SM     = 0x0C;
	/** Architecture v7E-M */
	public static final int PT_ARM_ARCHEXT_ARCHv7EM      = 0x0D;

	// FLAGS 

	/** This masks an 8-bit version number, the version of the ABI to which this ELF file conforms. This ABI is version 5. A value of 0 denotes unknown conformance. */
	public static final int EF_ARM_EABIMASK = 0xFF000000;
	/** The ELF file contains BE-8 code, suitable for execution on an ARM Architecture v6 processor. This flag must only be set on an executable file. */
	public static final int EF_ARM_BE8 = 0x00800000;

}
