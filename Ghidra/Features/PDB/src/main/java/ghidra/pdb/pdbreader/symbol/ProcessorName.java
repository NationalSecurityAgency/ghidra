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
package ghidra.pdb.pdbreader.symbol;

import java.util.HashMap;
import java.util.Map;

import ghidra.pdb.AbstractParsableItem;

/**
 * Procedure Name component for certain PDB symbols.
 */
public class ProcessorName extends AbstractParsableItem {

	private static final Map<Integer, String> processorStringMap = new HashMap<>();
	static {
		processorStringMap.put(0x00, "8080");
		processorStringMap.put(0x01, "8086");
		processorStringMap.put(0x02, "80286");
		processorStringMap.put(0x03, "80386");
		processorStringMap.put(0x04, "80486");
		processorStringMap.put(0x05, "Pentium");
		processorStringMap.put(0x06, "Pentium Pro/Pentium II");
		processorStringMap.put(0x07, "Pentium III");

		processorStringMap.put(0x10, "MIPS (Generic)");
		processorStringMap.put(0x11, "MIPS16");
		processorStringMap.put(0x12, "MIPS32");
		processorStringMap.put(0x13, "MIPS64");
		processorStringMap.put(0x14, "MIPS I");
		processorStringMap.put(0x15, "MIPS II");
		processorStringMap.put(0x16, "MIPS III");
		processorStringMap.put(0x17, "MIPS IV");
		processorStringMap.put(0x18, "MIPS V");

		processorStringMap.put(0x20, "M68000");
		processorStringMap.put(0x21, "M68010");
		processorStringMap.put(0x22, "M68020");
		processorStringMap.put(0x23, "M68030");
		processorStringMap.put(0x24, "M68040");

		processorStringMap.put(0x30, "Alpha 21064");
		processorStringMap.put(0x31, "Alpha 21164");
		processorStringMap.put(0x32, "Alpha 21164a");
		processorStringMap.put(0x33, "Alpha 21264");
		processorStringMap.put(0x34, "Alpha 21364");

		processorStringMap.put(0x40, "PPC 601");
		processorStringMap.put(0x41, "PPC 603");
		processorStringMap.put(0x42, "PPC 604");
		processorStringMap.put(0x43, "PPC 620");
		processorStringMap.put(0x44, "PPC w/FP");
		processorStringMap.put(0x45, "PPC (Big Endian)");

		processorStringMap.put(0x50, "SH3");
		processorStringMap.put(0x51, "SH3E");
		processorStringMap.put(0x52, "SH3DSP");
		processorStringMap.put(0x53, "SH4");
		processorStringMap.put(0x54, "SHmedia");

		processorStringMap.put(0x60, "ARMv3 (CE)");
		processorStringMap.put(0x61, "ARMv4 (CE)");
		processorStringMap.put(0x62, "ARMv4T (CE)");
		processorStringMap.put(0x63, "ARMv5 (CE)");
		processorStringMap.put(0x64, "ARMv5T (CE)");
		processorStringMap.put(0x65, "ARMv6 (CE)");
		processorStringMap.put(0x66, "ARM (XMAC) (CE)");
		processorStringMap.put(0x67, "ARM (XMMX) (CE)");
		processorStringMap.put(0x68, "ARMv7 (CE)");

		processorStringMap.put(0x70, "Omni");

		processorStringMap.put(0x80, "Itanium");
		processorStringMap.put(0x81, "Itanium (McKinley)");

		processorStringMap.put(0x90, "CEE");

		processorStringMap.put(0xa0, "AM33");

		processorStringMap.put(0xb0, "M32R");

		processorStringMap.put(0xc0, "TriCore");

		processorStringMap.put(0xd0, "x64");

		processorStringMap.put(0xe0, "EBC");

		processorStringMap.put(0xf0, "Thumb (CE)");
		processorStringMap.put(0xf4, "ARM");
		processorStringMap.put(0xf6, "ARM64");

		processorStringMap.put(0x100, "D3D11_SHADER");
	}

	private static final String badProcessor = "???";

	//==============================================================================================
	private int processorIndex;

	//==============================================================================================
	/**
	 * Constructor for this symbol component.  Requires argument for the processor index. 
	 * @param processorIndexIn Processor index.
	 */
	public ProcessorName(int processorIndexIn) {
		this.processorIndex = processorIndexIn;
	}

	/**
	 * Returns the processor index.
	 * @return Processor index.
	 */
	public int getProcessorIndex() {
		return processorIndex;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getProcessorName());
	}

	private String getProcessorName() {
		return processorStringMap.getOrDefault(processorIndex, badProcessor);
	}

}
