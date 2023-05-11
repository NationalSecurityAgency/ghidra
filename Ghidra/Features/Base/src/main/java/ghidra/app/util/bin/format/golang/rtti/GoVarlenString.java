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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.data.*;

/**
 * A pascal-ish string, using a LEB128 value as the length of the following bytes.
 * <p>
 * Used mainly in lower-level RTTI structures, this class is a ghidra'ism used to parse the
 * golang rtti data and does not have a counterpart in the golang src. 
 */
@StructureMapping(structureName = "GoVarlenString")
public class GoVarlenString implements StructureReader<GoVarlenString> {

	@ContextField
	private StructureContext<GoVarlenString> context;

	@FieldMapping(fieldName = "strlen")
	@FieldOutput(isVariableLength = true, getter = "strlenDataType")
	private int strlenLen; // store the len of the leb128, not the value of the leb128 number

	@FieldMapping(fieldName = "value")
	@FieldOutput(isVariableLength = true, getter = "valueDataType")
	private byte[] bytes;

	public GoVarlenString() {
	}

	@Override
	public void readStructure() throws IOException {
		readFrom(context.getReader());
	}

	private void readFrom(BinaryReader reader) throws IOException {
		long startPos = reader.getPointerIndex();
		int strLen = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		this.strlenLen = (int) (reader.getPointerIndex() - startPos);
		this.bytes = reader.readNextByteArray(strLen);
	}

	public int getStrlen() {
		return bytes.length;
	}

	public int getStrlenLen() {
		return strlenLen;
	}

	public byte[] getBytes() {
		return bytes;
	}

	public String getString() {
		return new String(bytes, StandardCharsets.UTF_8);
	}

	public DataTypeInstance getStrlenDataType() {
		return DataTypeInstance.getDataTypeInstance(UnsignedLeb128DataType.dataType, strlenLen,
			false);
	}

	public DataType getValueDataType() {
		return new ArrayDataType(CharDataType.dataType, bytes.length, -1,
			context.getDataTypeMapper().getDTM());
	}

}
