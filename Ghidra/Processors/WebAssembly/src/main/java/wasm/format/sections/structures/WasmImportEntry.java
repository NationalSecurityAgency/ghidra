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

import org.apache.commons.text.StringEscapeUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.WasmExternalKind;

public class WasmImportEntry implements StructConverter {

	private WasmName module;
	private WasmName field;
	private WasmExternalKind kind;

	private LEB128Info functionEntry;
	private WasmTableType tableEntry;
	private WasmResizableLimits memoryEntry;
	private WasmGlobalType globalEntry;

	private long startOffset, endOffset;

	public WasmImportEntry(BinaryReader reader) throws IOException {
		startOffset = reader.getPointerIndex();
		module = new WasmName(reader);
		field = new WasmName(reader);
		kind = WasmExternalKind.values()[reader.readNextByte()];
		switch (kind) {
		case EXT_FUNCTION:
			functionEntry = reader.readNext(LEB128Info::unsigned);
			break;
		case EXT_TABLE:
			tableEntry = new WasmTableType(reader);
			break;
		case EXT_MEMORY:
			memoryEntry = new WasmResizableLimits(reader);
			break;
		case EXT_GLOBAL:
			globalEntry = new WasmGlobalType(reader);
			break;
		default:
			break;
		}
		endOffset = reader.getPointerIndex();
	}

	public WasmExternalKind getKind() {
		return kind;
	}

	public int getFunctionType() {
		if (kind != WasmExternalKind.EXT_FUNCTION) {
			throw new IllegalArgumentException("Cannot get function type of non-function import");
		}
		return (int) functionEntry.asLong();
	}

	public WasmTableType getTableType() {
		if (kind != WasmExternalKind.EXT_TABLE) {
			throw new IllegalArgumentException("Cannot get table type of non-table import");
		}
		return tableEntry;
	}

	public WasmResizableLimits getMemoryType() {
		if (kind != WasmExternalKind.EXT_MEMORY) {
			throw new IllegalArgumentException("Cannot get memory type of non-memory import");
		}
		return memoryEntry;
	}

	public WasmGlobalType getGlobalType() {
		if (kind != WasmExternalKind.EXT_GLOBAL) {
			throw new IllegalArgumentException("Cannot get global type of non-global import");
		}
		return globalEntry;
	}

	public String getModule() {
		return module.getValue();
	}

	public String getName() {
		return field.getValue();
	}

	public long getEntryOffset() {
		return startOffset;
	}

	public long getEntrySize() {
		return endOffset - startOffset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("import_" + StringEscapeUtils.escapeJava(getName()));
		builder.add(module, "module");
		builder.add(field, "field");
		builder.add(BYTE, "kind");
		switch (kind) {
		case EXT_FUNCTION:
			builder.addUnsignedLeb128(functionEntry, "type");
			break;
		case EXT_TABLE:
			builder.add(tableEntry, "type");
			break;
		case EXT_MEMORY:
			builder.add(memoryEntry, "type");
			break;
		case EXT_GLOBAL:
			builder.add(globalEntry, "type");
			break;
		default:
			break;
		}
		return builder.toStructure();
	}
}
