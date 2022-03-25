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
package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmResizableLimits implements StructConverter {

	private int flags;
	private LEB128 initial;
	private LEB128 maximum;

	public WasmResizableLimits(BinaryReader reader) throws IOException {
		flags = reader.readNextUnsignedByte();
		initial = LEB128.readUnsignedValue(reader);
		if (flags == 1) {
			maximum = LEB128.readUnsignedValue(reader);
		}
	}

	public long getInitial() {
		return initial.asLong();
	}

	public long getMaximum() {
		if (maximum != null) {
			return maximum.asLong();
		}
		return -1;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("limits");
		builder.add(BYTE, "flags");
		builder.add(initial, "initial");
		if (maximum != null) {
			builder.add(maximum, "maximum");
		}
		return builder.toStructure();
	}
}
