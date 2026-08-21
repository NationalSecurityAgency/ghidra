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
package ghidra.app.util.bin.format.elf.info;

import static ghidra.app.util.bin.StructConverter.*;

import java.io.IOException;
import java.util.Objects;

import ghidra.app.cmd.comments.AppendCommentCmd;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * Represents an element from the .gnu.build.attributes section.
 * <p>
 * Technically this is a NOTE, but this class does not derive from ElfNote because the
 * implementation of build attributes takes liberties with the name field.
 */
public class GnuBuildAttribute implements ElfInfoItem {

	/**
	 * Reads a single {@link GnuBuildAttribute} from the specified stream.
	 * 
	 * @param reader {@link BinaryReader} stream
	 * @return new {@link GnuBuildAttribute}
	 * @throws IOException if error reading
	 */
	public static GnuBuildAttribute read(BinaryReader reader) throws IOException {
		int nameLen = reader.readNextUnsignedIntExact();
		int descLen = reader.readNextUnsignedIntExact();
		int vendorType = reader.readNextInt();
		if (nameLen > ElfNote.MAX_SANE_NAME_LEN || descLen > ElfNote.MAX_SANE_DESC_LEN) {
			throw new IOException("Invalid Note lengths: %d, %d".formatted(nameLen, descLen));
		}
		byte[] nameBytes = reader.readNextByteArray(nameLen);
		nameLen += reader.align(4);

		byte[] desc = reader.readNextByteArray(descLen);

		return new GnuBuildAttribute(nameLen, nameBytes, vendorType, desc);
	}

	enum ValueType {
		NUMERIC('*', "num"),
		STRING('$', "str"),
		BOOLEAN_FALSE('!', "bool"), // implied value
		BOOLEAN_TRUE('+', "bool"); // implied value

		private final char ch;
		private final String abbr;

		ValueType(char ch, String abbr) {
			this.ch = ch;
			this.abbr = abbr;
		}

		public String getAbbr() {
			return abbr;
		}

		private static final ValueType[] lookupValues = values();

		public static ValueType of(int ch) {
			for (ValueType e : lookupValues) {
				if (e.ch == ch) {
					return e;
				}
			}
			return null;
		}

	}

	enum AttributeId {
		RESERVED(0),
		VERSION(1),
		STACK_PROT(2),
		RELRO(3),
		STACKSIZE(4),
		TOOL(5),  // build tool & version
		ABI(6),
		POSITION_INDEPENDENCE(7), // 0 = static, 1 = pic, 2 = PIC, 3 = pie
		SHORT_ENUM(8),
		RESERVED1(9),
		// ...RESERVED 9..31
		STRINGVAL(31), // attribute's id is given by a string value starting here
		RESERVED2(127);

		private static final int RESERVED1_START = 9;
		private static final int RESERVED1_END = 31;
		private static final int RESERVED2_START = 127;
		private static final int FIRSTCHAR_START = 32;

		private final int idVal;

		AttributeId(int idVal) {
			this.idVal = idVal;
		}

		public int getIdVal() {
			return idVal;
		}

		private static final AttributeId[] lookupValues = values();

		public static AttributeId of(int idVal) {
			if (RESERVED1_START <= idVal && idVal <= RESERVED1_END) {
				return RESERVED1;
			}
			if (FIRSTCHAR_START <= idVal && idVal < RESERVED2_START) {
				return STRINGVAL;
			}
			if (RESERVED2_START <= idVal) {
				return RESERVED2;
			}
			for (AttributeId e : lookupValues) {
				if (e.idVal == idVal) {
					return e;
				}
			}
			return null;
		}
	}

	enum AttributeType {
		OPEN(0x100, "open range"), FUNC(0x101, "func symbol range");

		private final int typeInt;
		private final String desc;

		AttributeType(int typeInt, String desc) {
			this.typeInt = typeInt;
			this.desc = desc;
		}

		public int getTypeInt() {
			return typeInt;
		}

		public String getDescription() {
			return desc;
		}

		private static final AttributeType[] lookupValues = values();

		public static AttributeType of(int typeInt) {
			for (AttributeType e : lookupValues) {
				if (e.typeInt == typeInt) {
					return e;
				}
			}
			return null;
		}
	}

	private static final String GNU_ATTR_NAME_PREFIX = "GA";
	private static final int NAME_PREFIX_LEN = GNU_ATTR_NAME_PREFIX.length();
	private static final int KIND_OFFSET = NAME_PREFIX_LEN;
	private static final int ID_OFFSET = KIND_OFFSET + 1;

	// name field layout:
	// "GA" + value_type_char + Id_char + (id_string_bytes_null_term) + (value_bytes)
	// Example:
	// "GA$",01h,"3a1" -> string valued attribute, attribute_id(1)=version, value(string)="3a1"

	private final int nameLen; // may be different than nameBytes.length to force alignment
	private final byte[] nameBytes;
	private final int vendorType; // see AttributeType
	private final byte[] description; // must be len=0 or len=ptrsize*2

	public GnuBuildAttribute(int nameLen, byte[] nameBytes, int vendorType, byte[] description) {
		this.nameLen = nameLen;
		this.nameBytes = nameBytes;
		this.vendorType = vendorType;
		this.description = description;
	}

	public AttributeId getId() {
		if (nameBytes.length < ID_OFFSET + 1) {
			return null;
		}
		int ch = Byte.toUnsignedInt(nameBytes[ID_OFFSET]);
		return AttributeId.of(ch);
	}

	public String getIdString() {
		AttributeId id = getId();
		if (id == AttributeId.STRINGVAL) {
			try {
				// using utf8 is probably overkill as the rules for the id exclude byte values 127+ from
				// being the first char
				String s = getNameReader(true /* LE/BE doesn't matter */).readUtf8String(ID_OFFSET);
				return "\"%s\"".formatted(s);
			}
			catch (IOException e) {
				return "unknown";
			}
		}
		return id != null ? id.name() : "unknown";
	}

	public Object getValue(Program program) {
		try {
			ValueType valtype = getValueType();
			if (valtype == null) {
				return null;
			}
			BinaryReader reader = getNameReader(!program.getMemory().isBigEndian());
			reader.setPointerIndex(getValueOffset());
			return switch (valtype) {
				case STRING -> reader.readNextUtf8String();
				case NUMERIC -> reader.readNext(LEB128::unsigned);
				case BOOLEAN_FALSE -> false;
				case BOOLEAN_TRUE -> true;
				default -> null;
			};
		}
		catch (IOException e) {
			return null;
		}

	}

	private int getValueOffset() {
		AttributeId id = getId();
		if (id == AttributeId.STRINGVAL) {
			BinaryReader reader = getNameReader(true);
			try {
				reader.setPointerIndex(ID_OFFSET);
				reader.readNextUtf8String();
			}
			catch (IOException e) {
				// ignore
			}
			return (int) reader.getPointerIndex();
		}
		else {
			return ID_OFFSET + 1;
		}
	}

	private ValueType getValueType() {
		return nameBytes.length > NAME_PREFIX_LEN
				? ValueType.of(Byte.toUnsignedInt(nameBytes[NAME_PREFIX_LEN]))
				: null;
	}

	public AttributeType getAttributeType() {
		return AttributeType.of(vendorType);
	}

	public record AddressPair(Address first, Address second) {
		@Override
		public String toString() {
			return first.toString() + "-" + second.toString();
		}
	}

	public AddressPair getRange(Program program) {
		int ptrSize = program.getDefaultPointerSize();
		if (description.length == ptrSize * 2) {
			try {
				BinaryReader reader = getDescriptionReader(!program.getMemory().isBigEndian());
				long startOfs = reader.readNextUnsignedValue(ptrSize);
				long endOfs = reader.readNextUnsignedValue(ptrSize);
				// NOTE: some values will be the same indicating an empty range (which 
				// ghidra doesn't like), or some values will have start / end swapped, or 
				// some values may point to invalid locations (typically 1 past end of memory block)
				Address startAddr = program.getImageBase().getNewAddress(startOfs);
				Address endAddr = program.getImageBase().getNewAddress(endOfs - 1);
				return new AddressPair(startAddr, endAddr);
			}
			catch (IOException e) {
				// fall thru
			}
		}
		return null;
	}

	public String getLabel(Program program) {
		String idStr = getIdString();
		Object val = getValue(program);
		String valStr = val != null ? val.toString() : "unknown";

		AttributeType type = getAttributeType();
		String typeStr = type != null ? type.name() : "unknown";

		return "gnu.build.attribute_%s_%s=%s".formatted(typeStr, idStr, valStr);
	}

	public String getDescription(Program program) {
		String idStr = getIdString();
		Object val = getValue(program);
		String valStr = val != null ? val.toString() : "unknown";

		return "%s=%s".formatted(idStr, valStr);
	}

	@Override
	public void markupProgram(Program program, Address address) {
		StructureDataType dt = createNoteStructure(StandardElfInfoProducer.ELF_CATEGORYPATH,
			"GnuBuildAttribute", program, program.getDataTypeManager());
		if (dt != null) {
			try {
				AddressPair range = getRange(program);

				String attrComment = getDescription(program);
				if (range != null) {
					attrComment += ", range=" + range.toString();
				}
				appendComment(program, address, CommentType.EOL, "", attrComment, "\n");

				String label = SymbolUtilities.replaceInvalidChars(getLabel(program), true);
				program.getSymbolTable().createLabel(address, label, null, SourceType.IMPORTED);

				DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

				if (range != null) {
					Address startFieldAddr = getFieldAddr(dt, "start", address);
					Address endFieldAddr = getFieldAddr(dt, "end", address);

					if (startFieldAddr != null && endFieldAddr != null) {
						ReferenceManager refMgr = program.getReferenceManager();

						refMgr.addMemoryReference(startFieldAddr, range.first(), RefType.DATA,
							SourceType.IMPORTED, 0);
						refMgr.addMemoryReference(endFieldAddr, range.second(), RefType.DATA,
							SourceType.IMPORTED, 0);
					}
				}

			}
			catch (CodeUnitInsertionException | InvalidInputException e) {
				Msg.error(this, "Failed to markup Elf Note at %s: %s".formatted(address, this), e);
			}
		}
	}


	private Address getFieldAddr(Structure struct, String fieldName, Address startAddr) {
		for (DataTypeComponent dtc : struct.getDefinedComponents()) {
			if (fieldName.equals(dtc.getFieldName())) {
				return startAddr.add(dtc.getOffset());
			}
		}
		return null;
	}

	private BinaryReader getNameReader(boolean isLittleEndian) {
		ByteArrayProvider bap = new ByteArrayProvider(nameBytes);
		BinaryReader descReader = new BinaryReader(bap, isLittleEndian);
		return descReader;
	}

	private BinaryReader getDescriptionReader(boolean isLittleEndian) {
		ByteArrayProvider bap = new ByteArrayProvider(description);
		BinaryReader descReader = new BinaryReader(bap, isLittleEndian);
		return descReader;
	}

	private StructureDataType createNoteStructure(CategoryPath cp, String structName,
			Program program, DataTypeManager dtm) {

		cp = Objects.requireNonNullElse(cp, StandardElfInfoProducer.ELF_CATEGORYPATH);
		StructureDataType result = new StructureDataType(cp,
			"%s_%d_%d".formatted(structName, nameBytes.length, description.length), 0, dtm);
		result.add(DWORD, "namesz", "Length of name field");
		result.add(DWORD, "descsz", "Length of description field");
		result.add(DWORD, "type", "Vendor specific type");
		result.add(new ArrayDataType(ASCII, nameLen), "name", null);

		int ptrSize = program.getDefaultPointerSize();
		if (description.length == ptrSize * 2) {
			result.add(new PointerDataType(), "start", null);
			result.add(new PointerDataType(), "end", null);
		}
		else if (description.length != 0) {
			result.add(new ArrayDataType(BYTE, description.length), "unknown", null);
		}

		return result;
	}

	static void appendComment(Program program, Address address, CommentType commentType,
			String prefix, String comment, String sep) {
		if (comment == null || comment.isBlank()) {
			return;
		}
		CodeUnit cu = getCodeUnitForComment(program, address);
		if (cu != null) {
			String existingComment = cu.getComment(commentType);
			if (existingComment != null && existingComment.contains(comment)) {
				// don't add same comment twice
				return;
			}
		}
		AppendCommentCmd cmd = new AppendCommentCmd(address, commentType,
			Objects.requireNonNullElse(prefix, "") + comment, sep);
		cmd.applyTo(program);
	}

	static CodeUnit getCodeUnitForComment(Program program, Address address) {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu == null) {
			return null;
		}
		Address cuAddr = cu.getMinAddress();
		if (cu instanceof Data && !address.equals(cuAddr)) {
			Data data = (Data) cu;
			return data.getPrimitiveAt((int) address.subtract(cuAddr));
		}
		return cu;
	}
}
