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

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a scattered_relocation_info structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/reloc.h.auto.html">mach-o/reloc.h</a> 
 */
public class ScatteredRelocationInfo extends RelocationInfo {

	public final static int R_SCATTERED = 0x80000000;

	private int r_scattered;
	private int r_value;

	public static ScatteredRelocationInfo createScatteredRelocationInfo(
			FactoryBundledWithBinaryReader reader) throws IOException {
		ScatteredRelocationInfo scatteredRelocationInfo =
			(ScatteredRelocationInfo) reader.getFactory().create(ScatteredRelocationInfo.class);
		scatteredRelocationInfo.initScatteredRelocationInfo(reader);
		return scatteredRelocationInfo;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ScatteredRelocationInfo() {
	}

	private void initScatteredRelocationInfo(FactoryBundledWithBinaryReader reader)
			throws IOException {
		int mask = reader.readNextInt();

		r_scattered = ((mask & 0x80000000) >> 31) & 0x1;
		r_pcrel = ((mask & 0x40000000) >> 30);
		r_length = ((mask & 0x30000000) >> 28);
		r_type = ((mask & 0x0f000000) >> 24);
		r_address = ((mask & 0x00ffffff));

		r_value = reader.readNextInt();
	}

	/**
	 * Returns true this is a scattered relocation.
	 * @return true this is a scattered relocation
	 */
	public boolean isScattered() {
		return r_scattered == 1;
	}

	/**
	 * The address of the relocatable expression for the item in the file that
	 * needs to be updated if the address is changed. For relocatable
	 * expressions with the difference of two section addresses, the address
	 * from which to subtract (in mathematical terms, the minuend) is
	 * contained in the first relocation entry and the address to subtract (the
	 * subtrahend) is contained in the second relocation entry.
	 * @return
	 */
	public int getValue() {
		return r_value;
	}

	@Override
	public long[] toValues() {
		return new long[] { r_scattered, r_pcrel, r_length, r_type, r_address,
			r_value & 0xffffffffL };
	}

	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("Scattered:    " + isScattered());
		buffer.append('\n');
		buffer.append("PC Relocated: " + isPcRelocated());
		buffer.append('\n');
		buffer.append("Length:       " + Integer.toHexString(r_length) + getLengthInBytes());
		buffer.append('\n');
		buffer.append("Type:         " + Integer.toHexString(r_type));
		buffer.append('\n');
		buffer.append("Address:      " + Long.toHexString(r_address));
		buffer.append('\n');
		buffer.append("Value:        " + Integer.toHexString(r_value));
		buffer.append('\n');
		return buffer.toString();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("scattered_relocation_info", 0);
		struct.add(DWORD, "r_mask", "{r_scattered,r_pcrel,r_length,r_type,r_address}");
		struct.add(DWORD, "r_value", null);
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
