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
package ghidra.file.formats.android.dex.format;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class EncodedValue implements StructConverter {

	private byte value;
	private byte valueType;
	private byte valueArgs;

	private byte[] valueBytes;

	private EncodedArray array;
	private EncodedAnnotation annotation;

	public EncodedValue(BinaryReader reader) throws IOException {
		value = reader.readNextByte();
		valueType = (byte) (value & 0x1f);
		valueArgs = (byte) ((value & 0xe0) >> 5);

		// length of value[] is based on TYPE....

		switch (valueType) {
			case ValueFormats.VALUE_BYTE:
			case ValueFormats.VALUE_SHORT:
			case ValueFormats.VALUE_CHAR:
			case ValueFormats.VALUE_INT:
			case ValueFormats.VALUE_LONG:
			case ValueFormats.VALUE_FLOAT:
			case ValueFormats.VALUE_DOUBLE:
			case ValueFormats.VALUE_STRING:
			case ValueFormats.VALUE_TYPE:
			case ValueFormats.VALUE_FIELD:
			case ValueFormats.VALUE_METHOD:
			case ValueFormats.VALUE_ENUM: {
				valueBytes = reader.readNextByteArray(valueArgs + 1);
				break;
			}
			case ValueFormats.VALUE_ARRAY: {
				array = new EncodedArray(reader);
				break;
			}
			case ValueFormats.VALUE_ANNOTATION: {
				annotation = new EncodedAnnotation(reader);
				break;
			}
			case ValueFormats.VALUE_NULL: {
				break;// do nothing...
			}
			case ValueFormats.VALUE_BOOLEAN: {
				break;// do nothing...
			}
			default: {
				break;// do nothing...
			}
		}
	}

	public byte getValueArgs() {
		return valueArgs;
	}

	public byte getValueType() {
		return valueType;
	}

	public byte[] getValueBytes() {
		return valueBytes;
	}

	public byte getValueByte() {
		return valueBytes[0];
	}

	public EncodedArray getArray() {
		return array;
	}

	public EncodedAnnotation getAnnotation() {
		return annotation;
	}

	public boolean isValueBoolean() {
		return valueArgs == 1;
	}

	byte getValue() {
		return value;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StringBuilder builder =
			new StringBuilder("encoded_value_0x" + Integer.toHexString(value & 0xff));
		Structure structure = new StructureDataType(builder.toString(), 0);
		structure.add(BYTE, "valueType", null);
		switch (valueType) {
			case ValueFormats.VALUE_BYTE:
			case ValueFormats.VALUE_SHORT:
			case ValueFormats.VALUE_CHAR:
			case ValueFormats.VALUE_INT:
			case ValueFormats.VALUE_LONG:
			case ValueFormats.VALUE_FLOAT:
			case ValueFormats.VALUE_DOUBLE:
			case ValueFormats.VALUE_STRING:
			case ValueFormats.VALUE_TYPE:
			case ValueFormats.VALUE_FIELD:
			case ValueFormats.VALUE_METHOD:
			case ValueFormats.VALUE_ENUM: {
				int length = (valueArgs & 0xff) + 1;
				structure.add(new ArrayDataType(BYTE, length, BYTE.getLength()), "value", null);
				builder.append("_" + length);
				break;
			}
			case ValueFormats.VALUE_ARRAY: {
				builder.append("_" + array.getValues().length);
				structure.add(array.toDataType(), "value", null);
				break;
			}
			case ValueFormats.VALUE_ANNOTATION: {
				DataType dataType = annotation.toDataType();
				structure.add(dataType, "value", null);
				builder.append("_" + dataType.getName());
				break;
			}
			case ValueFormats.VALUE_NULL: {
				break;// do nothing
			}
			case ValueFormats.VALUE_BOOLEAN: {
				break;// do nothing
			}
			default: {
				//TODO throw new RuntimeException( "unsupported encoded value: 0x" + Integer.toHexString( valueType & 0xff ) );
			}
		}
		try {
			structure.setName(builder.toString());
		}
		catch (InvalidNameException e) {
			// ignore, should never happen
		}
		structure.setCategoryPath(new CategoryPath("/dex/encoded_value"));
		return structure;
	}
}
