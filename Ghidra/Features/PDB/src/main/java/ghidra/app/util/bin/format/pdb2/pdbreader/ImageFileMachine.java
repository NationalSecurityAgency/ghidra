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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractCompile2MsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.Compile3MsSymbol;

/**
 * Machine Type seen in the {@link PdbNewDebugInfo} header.  We also map in the Processor.
 * We are not exactly sure about why there are different but similar items: Machine Type and
 * Processor.  The {@link Processor} is what is specified in {@link AbstractCompile2MsSymbol} and
 * {@link Compile3MsSymbol} and what we save off in {@link AbstractPdb}, but
 * {@link ImageFileMachine} is what we see in the header of {@link PdbNewDebugInfo}.
 * @see <a href="https://docs.microsoft.com/en-us/windows/desktop/sysinfo/image-file-machine-constants">
 * Image File Machine Constants</a>
 * @see <a href="http://metadataconsulting.blogspot.com/2014/06/imagefilemachine-extensive-machine-type.html">
 * Also Image File Machine Constants</a>
 * @see <a href="https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-image_file_header">
 * Other use</a>
 */
public enum ImageFileMachine {
	UNKNOWN("Unknown", 0x0000, Processor.UNKNOWN),
	// Processor Guess
	TARGET_HOST("Interacts with the host and not a WOW64 guest", 0x0001, Processor.UNKNOWN),
	I386("Intel 386", 0x014c, Processor.I80386),
	I860("Intel I860", 0x014d, Processor.UNKNOWN), // Processor Guess
	R3000("MIPS little-endian, 0x160 big-endian", 0x0162, Processor.MIPS_MIPSR4000),
	R4000("MIPS little-endian", 0x0166, Processor.MIPS_MIPSR4000),
	R10000("MIPS little-endian", 0x0168, Processor.MIPS_MIPSR4000),
	WCEMIPSV2("MIPS little-endian WCE v2", 0x0169, Processor.MIPS_MIPSR4000), // Processor Guess
	ALPHA("Alpha_AXP", 0x0184, Processor.ALPHA_21064), // Processor Guess
	SH3("SH3 little-endian", 0x01a2, Processor.SH3),
	SH3DSP("SH3DSP", 0x01a3, Processor.SH3DSP), //
	SH3E("SH3E little-endian", 0x01a4, Processor.SH3), // Processor Guess
	SH4("SH4 little-endian", 0x01a6, Processor.SH4),
	SH5("SH5", 0x01a8, Processor.SH4),
	ARM("ARM Little-Endian", 0x01c0, Processor.ARM3),
	THUMB("ARM Thumb/Thumb-2 Little-Endian", 0x01c2, Processor.THUMB),
	ARMNT("ARM Thumb-2 Little-Endian", 0x01c4, Processor.ARMNT),
	AM33("TAM33BD", 0x01d3, Processor.AM33),
	POWERPC("IBM PowerPC Little-Endian", 0x01F0, Processor.PPC601),
	POWERPCFP("POWERPCFP", 0x01f1, Processor.PPCFP),
	POWERPCBE("POWERPCBE", 0x01f2, Processor.PPCBE),
	IA64("Intel 64", 0x0200, Processor.IA64_IA64_1),
	M68K("Motorola 68000", 0x0268, Processor.M68000), // Processor Guess
	MIPS16("MIPS16", 0x0266, Processor.MIPS16), // Set Processor diff than MSFT
	ALPHA64("ALPHA64", 0x0284, Processor.ALPHA_21064), // Processor Guess
	MIPSFPU("MIPSFPU", 0x0366, Processor.MIPS_MIPSR4000),
	MIPSFPU16("MIPSFPU16", 0x0466, Processor.MIPS_MIPSR4000),
	AXP64("AXP64", 0x0284, Processor.UNKNOWN), // Processor Guess
	TRICORE("Infineon", 0x0520, Processor.TRICORE),
	CEF("CEF", 0x0CEF, Processor.UNKNOWN), // Processor Guess
	EBC("EFI Byte Code", 0x0EBC, Processor.EBC),
	AMD64("AMD64 (K8)", 0x8664, Processor.X64_AMD64),
	M32R("M32R little-endian", 0x9041, Processor.M32R),
	ARM64("ARM64 Little-Endian", 0xAA64, Processor.ARM64),
	CEE("CEE", 0xC0EE, Processor.CEE);

	private static final Map<Integer, ImageFileMachine> BY_VALUE = new HashMap<>();
	static {
		for (ImageFileMachine val : values()) {
			BY_VALUE.put(val.value, val);
		}
	}

	private final String label;
	private final int value;
	private Processor processor;

	@Override
	public String toString() {
		return label;
	}

	public static ImageFileMachine fromValue(int val) {
		return BY_VALUE.getOrDefault(val, UNKNOWN);
	}

	public Processor getProcessor() {
		return processor;
	}

	private ImageFileMachine(String label, int value, Processor processor) {
		this.label = label;
		this.value = value;
		this.processor = processor;
	}

}
