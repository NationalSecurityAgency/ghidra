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
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliElementType;
import ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliParam;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableCustomAttribute.CliCustomAttributeRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMemberRef.CliMemberRefRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMethodDef.CliMethodDefRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexCustomAttributeType;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

public class CliBlobCustomAttrib extends CliBlob {

	private CliFixedArg[] fixedArgs;
	private CliNamedArg[] namedArgs;
	private short numNamed;

	// Fixed constants for validating the structure
	private static final short CLIBLOBCUSTOMATTRIB_PROLOG = 0x0001;
	private static final byte CLIBLOBCUSTOMATTRIB_TYPE_FIELD = 0x53;
	private static final byte CLIBLOBCUSTOMATTRIB_TYPE_PROPERTY = 0x54;

	// SerString processing constants to validate and convert the
	// length of the string
	private static final int CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_64 = 0x40;
	private static final int CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128 = 0x80;
	private static final int CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_192 = 0xC0;

	// UTF-8 boundaries that help detect the end of a string where
	// lengths aren't specified in FixedArg
	private static final int CLIBLOBCUSTOMATTRIB_UTF8_LOW = 0x1F;
	private static final int CLIBLOBCUSTOMATTRIB_UTF8_HIGH = 0x7F;

	private class CliFixedArg {
		private CliElementType elem;
		private Object value;

		public CliFixedArg(CliElementType elem, Object value) {
			this.elem = elem;
			this.value = value;
		}

		public CliElementType getElem() {
			return elem;
		}

		public Object getValue() {
			return value;
		}
	}

	private class CliNamedArg {
		private int fieldOrProp;
		private CliElementType fieldOrPropType;
		private String fieldOrPropName;

		public CliNamedArg(int fieldOrProp, CliElementType fieldOrPropType,
				String fieldOrPropName) {
			this.fieldOrProp = fieldOrProp;
			this.fieldOrPropType = fieldOrPropType;
			this.fieldOrPropName = fieldOrPropName;
		}

		public int getFieldOrProp() {
			return fieldOrProp;
		}

		public CliElementType getFieldOrPropType() {
			return fieldOrPropType;
		}

		public String getFieldOrPropName() {
			return fieldOrPropName;
		}
	}

	public CliBlobCustomAttrib(CliBlob blob, CliCustomAttributeRow row,
			CliStreamMetadata metadataStream) throws IOException {
		super(blob);

		BinaryReader reader = blob.getContentsReader();

		// Validate the blob prolog
		short prolog = reader.readNextShort();
		if (prolog != CLIBLOBCUSTOMATTRIB_PROLOG) {
			Msg.warn(this,
				getName() + " had unexpected prolog (0x" + Integer.toHexString(prolog) + ")");
			return;
		}

		// The location in the blob table for the actual CustomAttrib blob
		int valueIndex = row.valueIndex;

		// The entry in the MethodRef or MethodDef table that corresponds to the method
		// This is a CustomAttributeType coded index
		int typeIndex = row.typeIndex;

		// The entry of the parent table index, also a CustomAttributeType coded index
		int parentIndex = row.parentIndex;

		// The FixedArg parameters in the CustomAttrib blob are stored concatenated
		// against each other without delimeters or type indicators, so you have to look
		// back to the originating method signature to figure out what's what.

		CliParam[] params = null;
		try {
			// Get the table type and row for the attribute and depending on the type
			// get the parameters
			CliTypeTable tableType = CliIndexCustomAttributeType.getTableName(typeIndex);
			int tableRow = CliIndexCustomAttributeType.getRowIndex(typeIndex);

			if (tableType == CliTypeTable.MemberRef) {
				CliMemberRefRow memberRefRow =
					(CliMemberRefRow) metadataStream.getTable(tableType).getRow(tableRow);
				CliBlob memberRefBlob =
					metadataStream.getBlobStream().getBlob(memberRefRow.signatureIndex);
				CliSigMethodRef methodRefSig = new CliSigMethodRef(memberRefBlob);
				params = methodRefSig.getParams();
			}
			else if (tableType == CliTypeTable.MethodDef) {
				CliMethodDefRow methodDefRow =
					(CliMethodDefRow) metadataStream.getTable(tableType).getRow(tableRow);
				CliBlob methodDefBlob =
					metadataStream.getBlobStream().getBlob(methodDefRow.sigIndex);
				CliSigMethodDef methodDefSig = new CliSigMethodDef(methodDefBlob);
				params = methodDefSig.getParamTypes();
			}
		}
		catch (InvalidInputException e) {
			Msg.warn(this, "Unable to process the parameters in " + getName());
			return;
		}

		// Process zero to multiple FixedArgs
		if (params != null) {
			ArrayList<CliFixedArg> processFixedArgs = new ArrayList<>();
			for (CliParam param : params) {
				byte elemByte = reader.peekNextByte();
				if (elemByte == CliElementType.ELEMENT_TYPE_I.id()) {
					reader.readNextByte();

					// IntPtr followed by a string of the name of the element, the
					// length of which is not specified and must be read until a
					// non-printable UTF-8 character is encountered to signal the
					// end of the name

					StringBuilder sb = new StringBuilder();
					while ((reader.peekNextByte() > CLIBLOBCUSTOMATTRIB_UTF8_LOW) &&
						(reader.peekNextByte() < CLIBLOBCUSTOMATTRIB_UTF8_HIGH)) {
						sb.append((char) reader.readNextByte());
					}

					processFixedArgs
							.add(new CliFixedArg(CliElementType.ELEMENT_TYPE_I, sb.toString()));
				}
				else {
					// Process Elem types
					switch (param.getType().baseTypeCode) {
						case ELEMENT_TYPE_BOOLEAN:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextByte()));
							break;

						case ELEMENT_TYPE_CHAR:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextShort()));
							break;

						case ELEMENT_TYPE_I1:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextByte()));
							break;

						case ELEMENT_TYPE_U1:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextUnsignedByte()));
							break;

						case ELEMENT_TYPE_I2:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextShort()));
							break;

						case ELEMENT_TYPE_U2:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextUnsignedShort()));
							break;

						case ELEMENT_TYPE_I4:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextInt()));
							break;

						case ELEMENT_TYPE_U4:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextUnsignedInt()));
							break;

						case ELEMENT_TYPE_I8:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextLong()));
							break;

						case ELEMENT_TYPE_U8:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextByteArray(LongLongDataType.dataType.getLength())));
							break;

						case ELEMENT_TYPE_R4:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextByteArray(Float4DataType.dataType.getLength())));
							break;

						case ELEMENT_TYPE_R8:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextByteArray(Float8DataType.dataType.getLength())));
							break;

						case ELEMENT_TYPE_STRING:
							int length = readSerStringLength(reader);
							processFixedArgs
									.add(new CliFixedArg(param.getType().baseTypeCode, new String(
										reader.readNextByteArray(length), StandardCharsets.UTF_8)));
							break;

						case ELEMENT_TYPE_VALUETYPE:
							processFixedArgs.add(new CliFixedArg(param.getType().baseTypeCode,
								reader.readNextInt()));
							break;

						default:
							Msg.info(this,
								"Found a CustomAttrib with an unprocessed element type: " +
									param.getRepresentation());
					}
				}
			}

			fixedArgs = new CliFixedArg[processFixedArgs.size()];
			for (int i = 0; i < fixedArgs.length; i++) {
				fixedArgs[i] = processFixedArgs.get(i);
			}
		}

		// NumNamed
		numNamed = reader.readNextShort();

		// Process zero to multiple NamedArgs here
		ArrayList<CliNamedArg> processNamedArgs = new ArrayList<>();
		for (int i = 0; i < numNamed; i++) {
			byte fieldOrProp = reader.readNextByte();
			if ((fieldOrProp != CLIBLOBCUSTOMATTRIB_TYPE_FIELD) &&
				fieldOrProp != CLIBLOBCUSTOMATTRIB_TYPE_PROPERTY) {
				Msg.warn(this, "Invalid FieldOrProp value in NamedArg #" + (i + 1) + ": 0x" +
					Integer.toHexString(fieldOrProp));
				continue;
			}

			CliElementType fieldOrPropType = CliElementType.fromInt(reader.readNextByte());

			// Account for the null terminator
			int nameLen = readSerStringLength(reader) + 1;
			String fieldOrPropName =
				new String(reader.readNextByteArray(nameLen), StandardCharsets.UTF_8);

			processNamedArgs.add(new CliNamedArg(fieldOrProp, fieldOrPropType, fieldOrPropName));
		}

		if (processNamedArgs.size() > 0) {
			namedArgs = new CliNamedArg[processNamedArgs.size()];
			for (int i = 0; i < namedArgs.length; i++) {
				namedArgs[i] = processNamedArgs.get(i);
			}
		}
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(WORD, "PROLOG", "Magic (0x0001)");

		// Display the FixedArgs
		if (fixedArgs != null) {
			for (int i = 0; i < fixedArgs.length; i++) {
				switch (fixedArgs[i].elem) {
					case ELEMENT_TYPE_CHAR:
						struct.add(UTF16, "FixedArg_" + i, "Elem (" + fixedArgs[i].getElem() + ")");
						break;

					case ELEMENT_TYPE_I1:
					case ELEMENT_TYPE_U1:
					case ELEMENT_TYPE_BOOLEAN:
						struct.add(BYTE, "FixedArg_" + i, "Elem (" + fixedArgs[i].getElem() + ")");
						break;

					case ELEMENT_TYPE_I2:
					case ELEMENT_TYPE_U2:
						struct.add(WORD, "FixedArg_" + i, "Elem (" + fixedArgs[i].getElem() + ")");
						break;

					case ELEMENT_TYPE_I4:
					case ELEMENT_TYPE_U4:
					case ELEMENT_TYPE_R4:
					case ELEMENT_TYPE_VALUETYPE:
						struct.add(DWORD, "FixedArg_" + i, "Elem (" + fixedArgs[i].getElem() + ")");
						break;

					case ELEMENT_TYPE_I8:
					case ELEMENT_TYPE_U8:
					case ELEMENT_TYPE_R8:
						struct.add(QWORD, "FixedArg_" + i, "Elem (" + fixedArgs[i].getElem() + ")");

					case ELEMENT_TYPE_STRING:
						String s = (String) fixedArgs[i].value;
						int l = s.length();
						if (l < CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128) {
							struct.add(BYTE, "PackedLen", "");
						}
						else if (l < CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_192) {
							struct.add(WORD, "PackedLen", "");
						}
						else {
							struct.add(DWORD, "PackedLen", "");

						}
						struct.add(UTF8, ((String) fixedArgs[i].value).length(), "FixedArg_" + i,
							"");
						break;

					case ELEMENT_TYPE_I:
						struct.add(BYTE, "ELEMENT_TYPE_I", "");
						struct.add(UTF8, ((String) fixedArgs[i].value).length(), "FixedArg_" + i,
							"");
						break;

					default:
						Msg.warn(this, "Unprocessed FixedArg element type in CustomAttr #" +
							(i + 1) + ": " + fixedArgs[i].getElem().name());
						break;
				}
			}
		}

		struct.add(WORD, "NumNamed", "Number of NamedArgs to follow");

		// Display the NamedArgs
		if (namedArgs != null) {
			for (int i = 0; i < numNamed; i++) {
				if (namedArgs[i].getFieldOrProp() == CLIBLOBCUSTOMATTRIB_TYPE_FIELD) {
					struct.add(BYTE, "FieldOrProp", "FIELD");
				}
				else if (namedArgs[i].getFieldOrProp() == CLIBLOBCUSTOMATTRIB_TYPE_PROPERTY) {
					struct.add(BYTE, "FieldOrProp", "PROPERTY");
				}
				else {
					struct.add(BYTE, "FieldOrProp", "Unknown value");
				}

				struct.add(BYTE, "FieldOrPropType", namedArgs[i].getFieldOrPropType().name());

				int nameLen = namedArgs[i].getFieldOrPropName().length();
				if (nameLen < CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128) {
					struct.add(BYTE, "PackedLen", "");
				}
				else if (nameLen < CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_192) {
					struct.add(WORD, "PackedLen", "");
				}
				else {
					struct.add(DWORD, "PackedLen", "");

				}

				struct.add(UTF8, nameLen, "FieldOrPropName", "");
			}
		}

		return struct;
	}

	@Override
	public String getContentsName() {
		return "CustomAttrib";
	}

	@Override
	public String getContentsComment() {
		return "A CustomAttrib blob stores values of fixed or named parameters supplied when " +
			"instantiating a custom attribute";
	}

	@Override
	public String getRepresentation() {
		return "Blob (" + getContentsDataType().getDisplayName() + ")";
	}

	// SerStrings ("serialized strings") have a length field that varies in size
	// based on the length of the string. This measures and decodes the Byte, Word,
	// or DWord length field and returns it.
	private int readSerStringLength(BinaryReader reader) throws IOException {
		byte[] length;
		ByteBuffer buf;

		// The first byte is either the size or an indicator that we have more
		// size bytes ahead. Values contained in more than one bytes are stored
		// big-endian.
		byte firstByte = reader.readNextByte();

		if (firstByte < CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128) {
			// A size less than 128 indicates this is the only size byte
			return firstByte;
		}
		else if (firstByte < CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_192) {
			// A value in the first byte in range [128 - 191] indicates the size
			// is stored as a Word and the value in the highest bit must be unset
			length = new byte[] { firstByte, reader.readNextByte() };

			// Unset the highest bit if it's set
			if ((length[1] &
				CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128) == CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128) {
				length[1] ^= CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128;
			}

			// Convert from big-endian
			buf = ByteBuffer.wrap(length);
			buf.order(ByteOrder.BIG_ENDIAN);
			return buf.getShort();
		}
		else {
			// A value in the first byte > 128 indicates the size is stored as
			// a DWord and the first two bits must be unset
			length = new byte[4];
			length[0] = firstByte;
			length[1] = reader.readNextByte();
			length[2] = reader.readNextByte();
			length[3] = reader.readNextByte();

			// Unset what will become the highest two bits if they're set
			if ((length[3] &
				CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128) == CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128) {
				length[3] ^= CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128;
			}
			if ((length[3] &
				CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_64) == CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_64) {
				length[3] ^= CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_64;
			}

			// Convert from big-endian
			buf = ByteBuffer.wrap(length);
			buf.order(ByteOrder.BIG_ENDIAN);
			return buf.getInt();
		}
	}
}
