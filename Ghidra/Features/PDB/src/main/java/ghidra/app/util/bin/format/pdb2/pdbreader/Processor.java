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

/**
 * Target Processor (CPU Type).
 */
public enum Processor {

	UNKNOWN("???", -1),

	I8080("8080", 0x00),
	I8086("8086", 0x01),
	I80286("80286", 0x02),
	I80386("80386", 0x03),
	I80486("80486", 0x04),
	PENTIUM("Pentium", 0x05),
	PENTIUMPRO_PENTIUMII("Pentium Pro/Pentium II", 0x06),
	PENTIUMIII("Pentium III", 0x07),

	MIPS_MIPSR4000("MIPS (Generic)/R4000", 0x10),
	MIPS16("MIPS16", 0x11),
	MIPS32("MIPS32", 0x12),
	MIPS64("MIPS64", 0x13),
	MIPSI("MIPS I", 0x14),
	MIPSII("MIPS II", 0x15),
	MIPSIII("MIPS III", 0x16),
	MIPSIV("MIPS IV", 0x17),
	MIPSV("MIPS V", 0x18),

	M68000("M68000", 0x20),
	M68010("M68010", 0x21),
	M68020("M68020", 0x22),
	M68030("M68030", 0x23),
	M68040("M68040", 0x24),

	ALPHA_21064("Alpha/Alpha 21064", 0x30),
	ALPHA_21164("Alpha 21164", 0x31),
	ALPHA_21164A("Alpha 21164a", 0x32),
	ALPHA_21264("Alpha 21264", 0x33),
	ALPHA_21364("Alpha 21364", 0x34),

	PPC601("PPC 601", 0x40),
	PPC603("PPC 603", 0x41),
	PPC604("PPC 604", 0x42),
	PPC620("PPC 620", 0x43),
	PPCFP("PPC w/FP", 0x44),
	PPCBE("PPC (Big Endian)", 0x45),

	SH3("SH3", 0x50),
	SH3E("SH3E", 0x51),
	SH3DSP("SH3DSP", 0x52),
	SH4("SH4", 0x53),
	SHMEDIA("SHmedia", 0x54),

	ARM3("ARMv3 (CE)", 0x60),
	ARM4("ARMv4 (CE)", 0x61),
	ARM4T("ARMv4T (CE)", 0x62),
	ARM5("ARMv5 (CE)", 0x63),
	ARM5T("ARMv5T (CE)", 0x64),
	ARM6("ARMv6 (CE)", 0x65),
	ARM_XMAC("ARM (XMAC) (CE)", 0x66),
	ARM_WMMX("ARM (XMMX) (CE)", 0x67),
	ARM7("ARMv7 (CE)", 0x68),

	OMNI("Omni", 0x70),

	IA64_IA64_1("Itanium", 0x80),
	IA64_2("Itanium (McKinley)", 0x81),

	CEE("CEE", 0x90),

	AM33("AM33", 0xA0),

	M32R("M32R", 0xB0),

	TRICORE("TriCore", 0xC0),

	X64_AMD64("x64", 0xD0),

	EBC("EBC", 0xE0),

	THUMB("Thumb (CE)", 0xF0),
	ARMNT("ARM", 0xF4),
	ARM64("ARM64", 0xF6),

	D3D11_SHADER("D3D11_SHADER", 0x100),

	// Extras seen while processing files.  TODO: Evaluate these more later.
	UNK1AB("Unknown1ab", 0x1ab),
	UNK304("Unknown304", 0x304);

	private static final Map<Integer, Processor> BY_VALUE = new HashMap<>();
	static {
		for (Processor val : values()) {
			BY_VALUE.put(val.value, val);
		}
	}

	public final String label;
	private final int value;

	@Override
	public String toString() {
		return label;
	}

	public int getValue() {
		return value;
	}

	public static Processor fromValue(int val) {
		return BY_VALUE.getOrDefault(val, UNKNOWN);
	}

	private Processor(String label, int value) {
		this.label = label;
		this.value = value;
	}

}
