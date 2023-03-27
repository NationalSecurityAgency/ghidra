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
package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.sections.structures.WasmName;

public abstract class WasmCustomSection extends WasmSection {
	private WasmName name;
	private long customLength;

	protected WasmCustomSection(BinaryReader reader) throws IOException {
		super(reader);
		name = new WasmName(reader);
		customLength = getContentSize() - name.getSize();
	}

	public static WasmCustomSection create(BinaryReader reader) throws IOException {
		long initialOffset = reader.getPointerIndex();
		/* skip section header: id + contentLength */
		reader.readNextUnsignedByte();
		reader.readNext(LEB128Info::unsigned);

		String name = new WasmName(reader).getValue();
		reader.setPointerIndex(initialOffset);

		if (name.equals("name")) {
			return new WasmNameSection(reader);
		}

		return new WasmUnknownCustomSection(reader);
	}

	@Override
	protected void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException {
		builder.add(name, "name");
	}

	public String getCustomName() {
		return name.getValue();
	}

	public long getCustomSize() {
		return customLength;
	}
}
