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
import ghidra.app.util.bin.LEB128Info;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmFuncType implements StructConverter {

	@SuppressWarnings("unused")
	private int form; /* always 0 in this version */
	private LEB128Info paramCount;
	private ValType[] paramTypes;
	private LEB128Info returnCount;
	private ValType[] returnTypes;

	public WasmFuncType(BinaryReader reader) throws IOException {
		form = reader.readNextUnsignedByte();
		paramCount = reader.readNext(LEB128Info::unsigned);
		paramTypes = ValType.fromBytes(reader.readNextByteArray((int) paramCount.asLong()));
		returnCount = reader.readNext(LEB128Info::unsigned);
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
		builder.addUnsignedLeb128(paramCount, "param_count");
		builder.addArray(BYTE, (int) paramCount.asLong(), "param_types");
		builder.addUnsignedLeb128(returnCount, "return_count");
		builder.addArray(BYTE, (int) returnCount.asLong(), "return_types");
		return builder.toStructure();
	}
}
