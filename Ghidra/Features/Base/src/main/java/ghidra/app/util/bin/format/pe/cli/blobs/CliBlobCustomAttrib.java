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
import ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTableRow;
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

	private static final int CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_128 = 0x80;
	private static final int CLIBLOBCUSTOMATTRIB_STRING_BOUNDARY_192 = 0xC0;

	private static final int CLIBLOBCUSTOMATTRIB_STRING_SIZE_ONE = 0x01;
	private static final int CLIBLOBCUSTOMATTRIB_STRING_SIZE_TWO = 0x02;
	private static final int CLIBLOBCUSTOMATTRIB_STRING_SIZE_FOUR = 0x03;
	private static final int CLIBLOBCUSTOMATTRIB_STRING_SIZE_BITMASK = 0x3F;

	private static final int CLIBLOBCUSTOMATTRIB_STRING_INDICATOR_SHIFT = 0x06;
	private static final int CLIBLOBCUSTOMATTRIB_STRING_INDICATOR_BITMASK = 0x03;

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
			int tableRowIndex = CliIndexCustomAttributeType.getRowIndex(typeIndex);
			CliAbstractTableRow tableRow = metadataStream.getTable(tableType).getRow(tableRowIndex);

			if (tableType == CliTypeTable.MemberRef) {
				CliMemberRefRow memberRefRow = (CliMemberRefRow) tableRow;
				CliBlob memberRefBlob =
					metadataStream.getBlobStream().getBlob(memberRefRow.signatureIndex);
				CliSigMethodRef methodRefSig = new CliSigMethodRef(memberRefBlob);
				params = methodRefSig.getParams();
			}
			else if (tableType == CliTypeTable.MethodDef) {
				CliMethodDefRow methodDefRow = (CliMethodDefRow) tableRow;
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
		fixedArgs = processFixedArgs(reader, params).toArray(CliFixedArg[]::new);

		// Process zero to multiple NamedArgs here
		namedArgs = processNamedArgs(reader).toArray(CliNamedArg[]::new);
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(WORD, "PROLOG", "Magic (0x0001)");

		// Display the FixedArgs
		if (fixedArgs != null) {
			for (int i = 0; i < fixedArgs.length; i++) {
				CliElementType elem = fixedArgs[i].elem;

				switch (elem) {
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
			for (CliNamedArg cliNamedArg : namedArgs) {
				int fieldOrProp = cliNamedArg.getFieldOrProp();
				if (fieldOrProp == CLIBLOBCUSTOMATTRIB_TYPE_FIELD) {
					struct.add(BYTE, "FieldOrProp", "FIELD");
				}
				else if (fieldOrProp == CLIBLOBCUSTOMATTRIB_TYPE_PROPERTY) {
					struct.add(BYTE, "FieldOrProp", "PROPERTY");
				}
				else {
					struct.add(BYTE, "FieldOrProp", "Unknown value");
				}

				struct.add(BYTE, "FieldOrPropType", cliNamedArg.getFieldOrPropType().name());

				int nameLen = cliNamedArg.getFieldOrPropName().length();
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
		byte[] lengthBytes;
		int length = 0;
		ByteBuffer buf;

		// The first byte is either the size or an indicator that we have more
		// size bytes ahead. Values contained in more than one bytes are stored
		// big-endian.
		byte firstByte = reader.readNextByte();

		// Shift the highest two bits to the bottom and mask off to detect the
		// size of the field holding the size of the string (1, 2, or 4 bytes),
		// then cut the indicator bits off the first byte of the length.
		byte stringSizeIndicator = (byte) (firstByte >> CLIBLOBCUSTOMATTRIB_STRING_INDICATOR_SHIFT &
			CLIBLOBCUSTOMATTRIB_STRING_INDICATOR_BITMASK);
		firstByte = (byte) (firstByte & CLIBLOBCUSTOMATTRIB_STRING_SIZE_BITMASK);

		if (stringSizeIndicator <= CLIBLOBCUSTOMATTRIB_STRING_SIZE_ONE) {
			length = firstByte;
		}
		else if (stringSizeIndicator == CLIBLOBCUSTOMATTRIB_STRING_SIZE_TWO) {
			lengthBytes = new byte[] { firstByte, reader.readNextByte() };

			// Convert from big-endian
			buf = ByteBuffer.wrap(lengthBytes);
			buf.order(ByteOrder.BIG_ENDIAN);
			length = buf.getShort();
		}
		else if (stringSizeIndicator == CLIBLOBCUSTOMATTRIB_STRING_SIZE_FOUR) {
			lengthBytes = new byte[] { firstByte, reader.readNextByte(), reader.readNextByte(),
				reader.readNextByte() };

			// Convert from big-endian
			buf = ByteBuffer.wrap(lengthBytes);
			buf.order(ByteOrder.BIG_ENDIAN);
			length = buf.getInt();
		}

		return length;
	}

	private ArrayList<CliFixedArg> processFixedArgs(BinaryReader reader, CliParam[] params)
			throws IOException {
		ArrayList<CliFixedArg> processFixedArgs = new ArrayList<>();
		if (params == null) {
			return processFixedArgs;
		}

		for (CliParam param : params) {
			byte elemByte = reader.peekNextByte();
			if (elemByte == CliElementType.ELEMENT_TYPE_I.id()) {
				reader.readNextByte();

				// IntPtr followed by a string of the name of the element, the
				// length of which is not specified and must be read until a
				// non-printable UTF-8 character is encountered to signal the
				// end of the name

				StringBuilder sb = new StringBuilder();
				while (((reader.peekNextByte() &
					CLIBLOBCUSTOMATTRIB_UTF8_HIGH) > CLIBLOBCUSTOMATTRIB_UTF8_LOW) &&
					((reader.peekNextByte() &
						CLIBLOBCUSTOMATTRIB_UTF8_HIGH) < CLIBLOBCUSTOMATTRIB_UTF8_HIGH)) {
					sb.append((char) reader.readNextByte());
				}

				processFixedArgs.add(new CliFixedArg(CliElementType.ELEMENT_TYPE_I, sb.toString()));
			}
			else {
				// Process Elem types
				CliElementType baseTypeCode = param.getType().baseTypeCode;
				switch (baseTypeCode) {
					case ELEMENT_TYPE_BOOLEAN:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextByte());
						break;

					case ELEMENT_TYPE_CHAR:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextShort());
						break;

					case ELEMENT_TYPE_I1:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextByte());
						break;

					case ELEMENT_TYPE_U1:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextUnsignedByte());
						break;

					case ELEMENT_TYPE_I2:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextShort());
						break;

					case ELEMENT_TYPE_U2:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextUnsignedShort());
						break;

					case ELEMENT_TYPE_I4:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextInt());
						break;

					case ELEMENT_TYPE_U4:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextUnsignedInt());
						break;

					case ELEMENT_TYPE_I8:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextByte());
						processFixedArgs.add(
							new CliFixedArg(param.getType().baseTypeCode, reader.readNextLong()));
						break;

					case ELEMENT_TYPE_U8:
						addFixedArg(processFixedArgs, baseTypeCode,
							reader.readNextByteArray(LongLongDataType.dataType.getLength()));
						break;

					case ELEMENT_TYPE_R4:
						addFixedArg(processFixedArgs, baseTypeCode,
							reader.readNextByteArray(Float4DataType.dataType.getLength()));
						break;

					case ELEMENT_TYPE_R8:
						addFixedArg(processFixedArgs, baseTypeCode,
							reader.readNextByteArray(Float8DataType.dataType.getLength()));
						break;

					case ELEMENT_TYPE_STRING:
						int length = readSerStringLength(reader);
						if (length > 0) {
							addFixedArg(processFixedArgs, baseTypeCode, new String(
								reader.readNextByteArray(length), StandardCharsets.UTF_8));
						}
						break;

					case ELEMENT_TYPE_VALUETYPE:
						addFixedArg(processFixedArgs, baseTypeCode, reader.readNextInt());
						break;

					default:
						Msg.info(this,
							"A CustomAttrib with an unprocessed element type was deteceted: " +
								param.getRepresentation());
				}
			}
		}

		return processFixedArgs;
	}

	private void addFixedArg(ArrayList<CliFixedArg> fixedArgs, CliElementType baseTypeCode,
			Object value) {
		fixedArgs.add(new CliFixedArg(baseTypeCode, value));
	}

	private ArrayList<CliNamedArg> processNamedArgs(BinaryReader reader) throws IOException {
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

			// +1 to account for the null terminator
			int nameLen = readSerStringLength(reader) + 1;
			String fieldOrPropName =
				new String(reader.readNextByteArray(nameLen), StandardCharsets.UTF_8);

			processNamedArgs.add(new CliNamedArg(fieldOrProp, fieldOrPropType, fieldOrPropName));
		}

		return processNamedArgs;
	}
}
