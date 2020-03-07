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
package ghidra.app.util.bin.format.macho.dyld;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.macho.CpuSubTypes;
import ghidra.app.util.bin.format.macho.CpuTypes;
import ghidra.program.model.lang.*;

public final class DyldArchitecture {

	/** Magic value prefix */
	public final static String  DYLD_V1_SIGNATURE_PREFIX   =  "dyld_v1";

	/** Maximum length of any signature */
	public final static int     DYLD_V1_SIGNATURE_LEN      =  0x10;

	// @formatter:off
	public final static DyldArchitecture X86     = new DyldArchitecture( CpuTypes.CPU_TYPE_X86,     CpuSubTypes.CPU_SUBTYPE_MULTIPLE, "dyld_v1    i386", "i386",    Endian.LITTLE );
	public final static DyldArchitecture X86_64  = new DyldArchitecture( CpuTypes.CPU_TYPE_X86_64,  CpuSubTypes.CPU_SUBTYPE_MULTIPLE, "dyld_v1  x86_64", "x86_64",  Endian.LITTLE );
	public final static DyldArchitecture X86_64h = new DyldArchitecture( CpuTypes.CPU_TYPE_X86_64,  CpuSubTypes.CPU_SUBTYPE_MULTIPLE, "dyld_v1 x86_64h", "x86_64",  Endian.LITTLE );
	public final static DyldArchitecture POWERPC = new DyldArchitecture( CpuTypes.CPU_TYPE_POWERPC, CpuSubTypes.CPU_SUBTYPE_MULTIPLE, "dyld_v1     ppc", "rosetta", Endian.BIG );
	public final static DyldArchitecture ARMV6   = new DyldArchitecture( CpuTypes.CPU_TYPE_ARM,     CpuSubTypes.CPU_SUBTYPE_ARM_V6,   "dyld_v1   armv6", "armv6",   Endian.LITTLE );
	public final static DyldArchitecture ARMV7   = new DyldArchitecture( CpuTypes.CPU_TYPE_ARM,     CpuSubTypes.CPU_SUBTYPE_ARM_V7,   "dyld_v1   armv7", "arm7",    Endian.LITTLE );
	public final static DyldArchitecture ARMV7F  = new DyldArchitecture( CpuTypes.CPU_TYPE_ARM,     CpuSubTypes.CPU_SUBTYPE_ARM_V7F,  "dyld_v1  armv7f", "arm7",    Endian.LITTLE );
	public final static DyldArchitecture ARMV7S  = new DyldArchitecture( CpuTypes.CPU_TYPE_ARM,     CpuSubTypes.CPU_SUBTYPE_ARM_V7S,  "dyld_v1  armv7s", "arm7",    Endian.LITTLE );
	public final static DyldArchitecture ARMV7K  = new DyldArchitecture( CpuTypes.CPU_TYPE_ARM,     CpuSubTypes.CPU_SUBTYPE_ARM_V7K,  "dyld_v1  armv7k", "arm7",    Endian.LITTLE );
	public final static DyldArchitecture ARMV8A  = new DyldArchitecture( CpuTypes.CPU_TYPE_ARM_64,  CpuSubTypes.CPU_SUBTYPE_MULTIPLE, "dyld_v1   arm64", "AARCH64",    Endian.LITTLE );
	public final static DyldArchitecture ARMV8Ae = new DyldArchitecture(CpuTypes.CPU_TYPE_ARM_64,   CpuSubTypes.CPU_SUBTYPE_MULTIPLE, "dyld_v1  arm64e", "AARCH64", Endian.LITTLE);

	
	public final static DyldArchitecture [] ARCHITECTURES = new DyldArchitecture [] { X86, X86_64, X86_64h, POWERPC, ARMV6, ARMV7, ARMV7F, ARMV7S, ARMV7K, ARMV8A, ARMV8Ae };
	// @formatter:on
	
	/**
	 * Returns the architecture object with the given signature.
	 * Returns NULL if one does not exist.
	 * @param signature the signature string
	 * @return the architecture object with the given signature or NULL
	 */
	public final static DyldArchitecture getArchitecture(String signature) {
		for (DyldArchitecture architecture : ARCHITECTURES) {
			if (architecture.getSignature().equals(signature)) {
				return architecture;
			}
		}
		return null;
	}

	public final static DyldArchitecture getArchitecture(ByteProvider provider) throws IOException {
		byte [] signatureBytes = provider.readBytes(0, DYLD_V1_SIGNATURE_LEN);
		String signature = new String( signatureBytes );
		return getArchitecture( signature.trim() );
	}

	private int cpuType;
	private int cpuSubType;
	private String signature;
	private String processor;
	private Endian endianness;
	
	private DyldArchitecture(int cpuType, int cpuSubType, String signature, String processor, Endian endianness) {
		this.cpuType    = cpuType;
		this.cpuSubType = cpuSubType;
		this.signature  = signature;
		this.processor  = processor;
		this.endianness = endianness;

		if (signature.length() + 1 != DYLD_V1_SIGNATURE_LEN) {
			throw new IllegalArgumentException("invalid signature string length: "+signature);
		}
	}

	public int getCpuType() {
		return cpuType;
	}

	public int getCpuSubType() {
		return cpuSubType;
	}

	public String getSignature() {
		return signature;
	}

	public String getProcessor() {
		return processor;
	}

	public Endian getEndianness() {
		return endianness;
	}

	@Override
	public String toString() {
		return signature;
	}

	public LanguageCompilerSpecPair getLanguageCompilerSpecPair(LanguageService languageService) throws IOException {
		if ( this == X86 ) {
            return new LanguageCompilerSpecPair( new LanguageID("x86:LE:32:default"), new CompilerSpecID("gcc") );
		}
		else if (this == X86_64 || this == X86_64h) {
			return new LanguageCompilerSpecPair( new LanguageID("x86:LE:64:default"), new CompilerSpecID("gcc") );
		}
		else if ( this == POWERPC ) {
			return new LanguageCompilerSpecPair( new LanguageID("PowerPC:BE:32:default"), new CompilerSpecID("macosx") );
		}
		if ( this == ARMV6 ) {
			return new LanguageCompilerSpecPair( new LanguageID("ARM:LE:32:v6"), new CompilerSpecID("default") );
		}
		else if ( this == ARMV7 ) {
			return new LanguageCompilerSpecPair( new LanguageID("ARM:LE:32:v7"), new CompilerSpecID("default"));
		}
		else if ( this == ARMV7S ) {//TODO support ARMV7S language....
			return new LanguageCompilerSpecPair( new LanguageID("ARM:LE:32:v7"), new CompilerSpecID("default"));
		}
		throw new LanguageNotFoundException("Unable to locate language for "+this);
	}
}
