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
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.golang.GoVer;
import ghidra.app.util.bin.format.golang.GoVerRange;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.model.data.*;
import ghidra.util.BigEndianDataConverter;

/**
 * A pascal-ish string, using a LEB128 (or a uint16 in pre-1.16) value as the length of the
 * following bytes.
 * <p>
 * Used mainly in lower-level RTTI structures, this class is a ghidra'ism used to parse the
 * golang rtti data and does not have a counterpart in the golang src. 
 */
@StructureMapping(structureName = "GoVarlenString")
public class GoVarlenString implements StructureReader<GoVarlenString> {
	
	private static final GoVerRange VERSIONS_THAT_USE_LEB128 = GoVerRange.parse("1.17+");

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

	private boolean useLEB128() {
		GoVer ver = ((GoRttiMapper) context.getDataTypeMapper()).getGoVer();
		return VERSIONS_THAT_USE_LEB128.contains(ver);
	}

	private void readFrom(BinaryReader reader) throws IOException {
		long startPos = reader.getPointerIndex();
		int strLen = useLEB128()
				? reader.readNextUnsignedVarIntExact(LEB128::unsigned)
				: reader.readNextUnsignedShort(BigEndianDataConverter.INSTANCE);
		this.strlenLen = (int) (reader.getPointerIndex() - startPos);
		this.bytes = reader.readNextByteArray(strLen);
	}

	/**
	 * Returns the string's length
	 * 
	 * @return string's length
	 */
	public int getStrlen() {
		return bytes.length;
	}

	/**
	 * Returns the size of the string length field.  
	 * 
	 * @return size of the string length field
	 */
	public int getStrlenLen() {
		return strlenLen;
	}

	/**
	 * Returns the raw bytes of the string
	 * 
	 * @return raw bytes of the string
	 */
	public byte[] getBytes() {
		return bytes;
	}

	/**
	 * Returns the string value.
	 * 
	 * @return string value
	 */
	public String getString() {
		return new String(bytes, StandardCharsets.UTF_8);
	}

	/**
	 * Returns the data type that is needed to hold the string length field.
	 * 
	 * @return data type needed to hold the string length field
	 */
	public DataTypeInstance getStrlenDataType() {
		DataType dt = useLEB128()
				? UnsignedLeb128DataType.dataType
				: AbstractIntegerDataType.getUnsignedDataType(2, null);

		return DataTypeInstance.getDataTypeInstance(dt, strlenLen, false);
	}

	/**
	 * Returns the data type that holds the raw string value.
	 * 
	 * @return data type that holds the raw string value.
	 */
	public DataType getValueDataType() {
		return new ArrayDataType(CharDataType.dataType, bytes.length, -1,
			context.getDataTypeMapper().getDTM());
	}

	@Override
	public String toString() {
		return String.format("GoVarlenString [context=%s, strlenLen=%s, bytes=%s, getString()=%s]",
			context, strlenLen, Arrays.toString(bytes), getString());
	}
}
