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
import wasm.format.WasmEnums.ValType;

public class WasmFuncType implements StructConverter {

	@SuppressWarnings("unused")
	private int form; /* always 0 in this version */
	private LEB128 paramCount;
	private ValType[] paramTypes;
	private LEB128 returnCount;
	private ValType[] returnTypes;

	public WasmFuncType(BinaryReader reader) throws IOException {
		form = reader.readNextUnsignedByte();
		paramCount = LEB128.readUnsignedValue(reader);
		paramTypes = ValType.fromBytes(reader.readNextByteArray((int) paramCount.asLong()));
		returnCount = LEB128.readUnsignedValue(reader);
		returnTypes = ValType.fromBytes(reader.readNextByteArray((int) returnCount.asLong()));
	}

	public ValType[] getParamTypes() {
		return paramTypes;
	}

	public ValType[] getReturnTypes() {
		return returnTypes;
	}

	private static String typeTupleToString(ValType[] types) {
		StringBuilder result = new StringBuilder();
		result.append("(");
		for (int i = 0; i < types.length; i++) {
			if (i != 0) {
				result.append(",");
			}
			result.append(types[i]);
		}
		result.append(")");
		return result.toString();
	}

	@Override
	public String toString() {
		return typeTupleToString(paramTypes) + "->" + typeTupleToString(returnTypes);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("func_type_" + paramCount.asLong() + "_" + returnCount.asLong());
		builder.add(BYTE, "form");
		builder.add(paramCount, "param_count");
		builder.addArray(BYTE, (int) paramCount.asLong(), "param_types");
		builder.add(returnCount, "return_count");
		builder.addArray(BYTE, (int) returnCount.asLong(), "return_types");
		return builder.toStructure();
	}
}
