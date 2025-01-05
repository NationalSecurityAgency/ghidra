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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmCodeEntry implements StructConverter {

	private LEB128Info codeSize;
	private List<WasmLocalEntry> locals = new ArrayList<WasmLocalEntry>();
	private LEB128Info localCount;
	private long codeOffset;
	private byte[] instructions;

	public WasmCodeEntry(BinaryReader reader) throws IOException {
		codeSize = reader.readNext(LEB128Info::unsigned);
		codeOffset = reader.getPointerIndex();
		localCount = reader.readNext(LEB128Info::unsigned);
		for (int i = 0; i < localCount.asLong(); ++i) {
			locals.add(new WasmLocalEntry(reader));
		}
		instructions = reader.readByteArray(codeOffset, codeSize.asInt32());
		reader.setPointerIndex(codeOffset + codeSize.asLong());
	}

	public LEB128Info getCodeSizeLeb128() {
		return codeSize;
	}

	public long getCodeSize() {
		return codeSize.asLong();
	}

	public long getOffset() {
		return codeOffset;
	}

	public byte[] getInstructions() {
		return instructions;
	}

	public ValType[] getLocals() {
		int localCount = 0;
		for (WasmLocalEntry local : locals) {
			localCount += local.getCount();
		}
		ValType[] result = new ValType[localCount];
		int pos = 0;
		for (WasmLocalEntry local : locals) {
			Arrays.fill(result, pos, pos + local.getCount(), ValType.fromByte(local.getType()));
			pos += local.getCount();
		}
		return result;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("code_" + codeOffset);
		builder.addUnsignedLeb128(codeSize, "code_size");
		builder.addArray(BYTE, instructions.length, "instructions");
		return builder.toStructure();
	}
}
