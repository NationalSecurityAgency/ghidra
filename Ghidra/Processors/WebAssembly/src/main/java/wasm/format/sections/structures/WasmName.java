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
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public class WasmName implements StructConverter {
	private LEB128Info size;
	private String value;

	public WasmName(BinaryReader reader) throws IOException {
		size = reader.readNext(LEB128Info::unsigned);
		if (size.asLong() == 0) {
			value = "";
		} else {
			byte[] data = reader.readNextByteArray((int) size.asLong());
			value = new String(data, StandardCharsets.UTF_8);
		}
	}

	public long getSize() {
		return size.getLength() + size.asLong();
	}

	public String getValue() {
		return value;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("name_" + size.asLong());
		builder.addUnsignedLeb128(size, "size");
		builder.addString((int) size.asLong(), "value");
		return builder.toStructure();
	}
}
