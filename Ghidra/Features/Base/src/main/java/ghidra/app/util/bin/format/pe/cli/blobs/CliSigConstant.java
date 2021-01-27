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
package ghidra.app.util.bin.format.pe.cli.blobs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

public class CliSigConstant extends CliAbstractSig {
	private CliElementType type;
	private Object value;

	public CliSigConstant(CliBlob blob, CliElementType elementType) throws IOException {
		super(blob);

		type = elementType;

		BinaryReader reader = blob.getContentsReader();
		switch (type) {
			case ELEMENT_TYPE_BOOLEAN:
			case ELEMENT_TYPE_CHAR:
				value = reader.readNextByte();
				break;

			case ELEMENT_TYPE_U2:
				value = reader.readNextUnsignedShort();
				break;

			case ELEMENT_TYPE_I2:
				value = reader.readNextShort();
				break;

			case ELEMENT_TYPE_U4:
				value = reader.readNextUnsignedInt();
				break;

			case ELEMENT_TYPE_I4:
				value = reader.readNextInt();
				break;

			case ELEMENT_TYPE_R4:
				value = ByteBuffer.wrap(reader.readNextByteArray(Float.BYTES))
						.order(ByteOrder.LITTLE_ENDIAN)
						.getFloat();
				break;

			case ELEMENT_TYPE_U8:
				value = ByteBuffer.wrap(reader.readNextByteArray(Long.BYTES)).getLong();
				break;

			case ELEMENT_TYPE_I8:
				value = reader.readNextLong();
				break;

			case ELEMENT_TYPE_R8:
				value = ByteBuffer.wrap(reader.readNextByteArray(Double.BYTES))
						.order(ByteOrder.LITTLE_ENDIAN)
						.getDouble();
				break;

			case ELEMENT_TYPE_STRING:
				byte[] stringConstantBytes = reader.readNextByteArray(contentsSize);
				value = new String(stringConstantBytes, StandardCharsets.UTF_16LE);
				break;

			default:
				Msg.warn(this, "An unrecognized data type was detected in a Constant blob: type " +
					elementType.name() + " @ " + blob.getName());
				return;
		}
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);

		switch (type) {
			case ELEMENT_TYPE_BOOLEAN:
			case ELEMENT_TYPE_CHAR:
				struct.add(BYTE, type.name(), "");
				break;

			case ELEMENT_TYPE_U2:
				struct.add(WORD, type.name(), "");
				break;

			case ELEMENT_TYPE_I2:
				if ((int) value < 0) {
					struct.add(WORD, type.name(), getRepresentation());
				}
				else {
					struct.add(WORD, type.name(), "");
				}
				break;

			case ELEMENT_TYPE_U4:
				struct.add(DWORD, type.name(), "");
				break;

			case ELEMENT_TYPE_I4:
				if ((int) value < 0) {
					struct.add(DWORD, type.name(), getRepresentation());
				}
				else {
					struct.add(DWORD, type.name(), "");
				}
				break;

			case ELEMENT_TYPE_R4:
				struct.add(DWORD, type.name(), getRepresentation());
				break;

			case ELEMENT_TYPE_U8:
				struct.add(QWORD, type.name(), "");
				break;

			case ELEMENT_TYPE_I8:
				if ((long) value < 0) {
					struct.add(QWORD, type.name(), getRepresentation());
				}
				else {
					struct.add(QWORD, type.name(), "");
				}
				break;

			case ELEMENT_TYPE_R8:
				struct.add(QWORD, type.name(), getRepresentation());
				break;

			case ELEMENT_TYPE_STRING:
				struct.add(UTF16, contentsSize, type.name(), "");
				break;
		}
		return struct;
	}

	@Override
	public String getContentsName() {
		return "ConstantSig";
	}

	@Override
	public String getContentsComment() {
		return "Data stored in a constant";
	}

	@Override
	public String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		return value.toString();
	}
}
