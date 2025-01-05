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
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;

public abstract class WasmSection implements StructConverter {
	
	private WasmSectionId id;
	private LEB128Info contentLength;
	private long sectionOffset;

	public enum WasmSectionId {
		SEC_CUSTOM,
		SEC_TYPE,
		SEC_IMPORT,
		SEC_FUNCTION,
		SEC_TABLE,
		SEC_LINEARMEMORY,
		SEC_GLOBAL,
		SEC_EXPORT,
		SEC_START,
		SEC_ELEMENT,
		SEC_CODE,
		SEC_DATA
	}
	
	public static WasmSection createSection(BinaryReader reader) throws IOException {
		long sectionOffset = reader.getPointerIndex();
		int id = reader.readNextUnsignedByte();
		LEB128Info contentLength = reader.readNext(LEB128Info::unsigned);
		reader.setPointerIndex(reader.getPointerIndex() + contentLength.asLong());

		if(id >= WasmSectionId.values().length)
			return null;

		BinaryReader sectionReader = reader.clone(sectionOffset);

		switch (WasmSectionId.values()[id]) {
			case SEC_CUSTOM:
				return WasmCustomSection.create(sectionReader);
			case SEC_TYPE:
				return new WasmTypeSection(sectionReader);
			case SEC_IMPORT:
				return new WasmImportSection(sectionReader);
			case SEC_FUNCTION:
				return new WasmFunctionSection(sectionReader);
			case SEC_TABLE:
				return new WasmTableSection(sectionReader);
			case SEC_LINEARMEMORY:
				return new WasmLinearMemorySection(sectionReader);
			case SEC_GLOBAL:
				return new WasmGlobalSection(sectionReader);
			case SEC_EXPORT:
				return new WasmExportSection(sectionReader);
			case SEC_START:
				return new WasmStartSection(sectionReader);
			case SEC_ELEMENT:
				return new WasmElementSection(sectionReader);
			case SEC_CODE:
				return new WasmCodeSection(sectionReader);
			case SEC_DATA:
				return new WasmDataSection(sectionReader);
			default:
				return null;
		}
	}
	
	protected WasmSection(BinaryReader reader) throws IOException {
		sectionOffset = reader.getPointerIndex();
		id = WasmSectionId.values()[reader.readNextUnsignedByte()];
		contentLength = reader.readNext(LEB128Info::unsigned);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder(getName());
		builder.add(BYTE, "id");
		builder.addUnsignedLeb128(contentLength, "size");
		addToStructure(builder);
		return builder.toStructure();
	}
	
	public abstract String getName();

	protected abstract void addToStructure(StructureBuilder builder) throws DuplicateNameException, IOException;

	public WasmSectionId getId() {
		return id;
	}

	public long getSectionOffset() {
		return sectionOffset;
	}

	public long getContentSize() {
		return contentLength.asLong();
	}

	public long getSectionSize() {
		return 1 + contentLength.getLength() + contentLength.asLong();
	}
}
