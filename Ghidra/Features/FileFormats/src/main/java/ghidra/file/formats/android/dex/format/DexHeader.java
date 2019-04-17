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

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.NumericUtilities;
import ghidra.util.datastruct.FixedSizeHashMap;
import ghidra.util.exception.DuplicateNameException;

public class DexHeader implements StructConverter {

	private byte[] magic;
	private byte [] version;
	private int checksum;
	private byte[] signature;
	private int fileSize;
	private int headerSize;
	private int endianTag;
	private int linkSize;
	private int linkOffset;
	private int mapOffset;
	private int stringIdsSize;
	private int stringIdsOffset;
	private int typeIdsSize;
	private int typeIdsOffset;
	private int protoIdsSize;
	private int protoIdsOffset;
	private int fieldIdsSize;
	private int fieldIdsOffset;
	private int methodIdsSize;
	private int methodIdsOffset;
	private int classDefsIdsSize;
	private int classDefsIdsOffset;
	private int dataSize;
	private int dataOffset;

	private MapList mapList;
	private List<StringIDItem> strings = new ArrayList<>();
	private List<TypeIDItem> types = new ArrayList<>();
	private List<PrototypesIDItem> prototypes = new ArrayList<>();
	private List<FieldIDItem> fields = new ArrayList<>();
	private List<MethodIDItem> methods = new ArrayList<>();
	private List<ClassDefItem> classDefs = new ArrayList<>();

	private AddressCache methodXref = new AddressCache(); // Index to method address cache
	private DataTypeCache typeXref = new DataTypeCache(); // Index to datatype cache

	public static class AddressCache extends FixedSizeHashMap<Integer, Address> {
		private static final int MAX_ENTRIES = 500;

		public AddressCache() {
			super(700, MAX_ENTRIES);
		}
	}

	public static class DataTypeCache extends FixedSizeHashMap<Integer, DataType> {
		private static final int MAX_ENTRIES = 100;

		public DataTypeCache() {
			super(150, MAX_ENTRIES);
		}
	}

	public DexHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextByteArray( DexConstants.DEX_MAGIC_BASE.length( ) );
		version = reader.readNextByteArray( DexConstants.DEX_VERSION_LENGTH );

		if (!DexConstants.DEX_MAGIC_BASE.equals(new String(magic))) {
			throw new IOException("not a dex file.");
		}

		checksum = reader.readNextInt();
		signature = reader.readNextByteArray(20);
		fileSize = reader.readNextInt();
		headerSize = reader.readNextInt();
		endianTag = reader.readNextInt();
		linkSize = reader.readNextInt();
		linkOffset = reader.readNextInt();
		mapOffset = reader.readNextInt();
		stringIdsSize = reader.readNextInt();
		stringIdsOffset = reader.readNextInt();
		typeIdsSize = reader.readNextInt();
		typeIdsOffset = reader.readNextInt();
		protoIdsSize = reader.readNextInt();
		protoIdsOffset = reader.readNextInt();
		fieldIdsSize = reader.readNextInt();
		fieldIdsOffset = reader.readNextInt();
		methodIdsSize = reader.readNextInt();
		methodIdsOffset = reader.readNextInt();
		classDefsIdsSize = reader.readNextInt();
		classDefsIdsOffset = reader.readNextInt();
		dataSize = reader.readNextInt();
		dataOffset = reader.readNextInt();

		reader.setPointerIndex(mapOffset);
		if (mapOffset > 0) {
			mapList = new MapList(reader);
		}

		reader.setPointerIndex(stringIdsOffset);
		for (int i = 0; i < stringIdsSize; ++i) {
			strings.add(new StringIDItem(reader));
		}

		reader.setPointerIndex(typeIdsOffset);
		for (int i = 0; i < typeIdsSize; ++i) {
			types.add(new TypeIDItem(reader));
		}

		reader.setPointerIndex(protoIdsOffset);
		for (int i = 0; i < protoIdsSize; ++i) {
			prototypes.add(new PrototypesIDItem(reader));
		}

		reader.setPointerIndex(fieldIdsOffset);
		for (int i = 0; i < fieldIdsSize; ++i) {
			fields.add(new FieldIDItem(reader));
		}

		reader.setPointerIndex(methodIdsOffset);
		for (int i = 0; i < methodIdsSize; ++i) {
			methods.add(new MethodIDItem(reader));
		}

		reader.setPointerIndex(classDefsIdsOffset);
		for (int i = 0; i < classDefsIdsSize; ++i) {
			classDefs.add(new ClassDefItem(reader));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("header_item", 0);
		structure.add(UTF8, 8, "magic", null);
		structure.add(DWORD, "checksum", "adler-32");
		String comment = "SHA1:" + NumericUtilities.convertBytesToString(signature);
		structure.add(new ArrayDataType(BYTE, 20, BYTE.getLength()), "signature", comment);
		structure.add(DWORD, "fileSize", null);
		structure.add(DWORD, "headerSize", null);
		structure.add(DWORD, "endianTag", null);
		structure.add(DWORD, "linkSize", null);
		structure.add(DWORD, "linkOffset", null);
		structure.add(DWORD, "mapOffset", null);
		structure.add(DWORD, "stringIdsSize", null);
		structure.add(DWORD, "stringIdsOffset", null);
		structure.add(DWORD, "typeIdsSize", null);
		structure.add(DWORD, "typeIdsOffset", null);
		structure.add(DWORD, "protoIdsSize", null);
		structure.add(DWORD, "protoIdsOffset", null);
		structure.add(DWORD, "fieldIdsSize", null);
		structure.add(DWORD, "fieldIdsOffset", null);
		structure.add(DWORD, "methodIdsSize", null);
		structure.add(DWORD, "methodIdsOffset", null);
		structure.add(DWORD, "classDefsIdsSize", null);
		structure.add(DWORD, "classDefsIdsOffset", null);
		structure.add(DWORD, "dataSize", null);
		structure.add(DWORD, "dataOffset", null);
		structure.setCategoryPath(new CategoryPath("/dex"));
		return structure;
	}

	public byte[] getMagic() {
		return magic;
	}

	public byte [] getVersion( ) {
		return version;
	}

	/**
	 * Adler32 checksum of the rest of the file (everything but magic and this field);
	 * used to detect file corruption 
	 */
	public int getChecksum() {
		return checksum;
	}

	/**
	 * SHA-1 signature (hash) of the rest of the file (everything but magic, checksum, and this field); 
	 * used to uniquely identify files 
	 */
	public byte[] getSignature() {
		return signature;
	}

	/**
	 * Size of the entire file (including the header), in bytes 
	 */
	public int getFileSize() {
		return fileSize;
	}

	/**
	 * Size of the header (this entire section), in bytes. 
	 * This allows for at least a limited amount of 
	 * backwards/forwards compatibility without invalidating the format. 
	 */
	public int getHeaderSize() {
		return headerSize;
	}

	/**
	 * Endianness tag. Either "ENDIAN_CONSTANT or REVERSE_ENDIAN_CONSTANT". 
	 */
	public int getEndianTag() {
		return endianTag;
	}

	public int getStringIdsOffset() {
		return stringIdsOffset;
	}

	public int getStringIdsSize() {
		return stringIdsSize;
	}

	public List<StringIDItem> getStrings() {
		return Collections.unmodifiableList(strings);
	}

	public int getClassDefsIdsOffset() {
		return classDefsIdsOffset;
	}

	public int getClassDefsIdsSize() {
		return classDefsIdsSize;
	}

	public List<ClassDefItem> getClassDefs() {
		return Collections.unmodifiableList(classDefs);
	}

	public int getDataOffset() {
		return dataOffset;
	}

	public int getDataSize() {
		return dataSize;
	}

	public int getFieldIdsOffset() {
		return fieldIdsOffset;
	}

	public int getFieldIdsSize() {
		return fieldIdsSize;
	}

	public List<FieldIDItem> getFields() {
		return Collections.unmodifiableList(fields);
	}

	public int getMethodIdsOffset() {
		return methodIdsOffset;
	}

	public int getMethodIdsSize() {
		return methodIdsSize;
	}

	public List<MethodIDItem> getMethods() {
		return Collections.unmodifiableList(methods);
	}

	public int getTypeIdsOffset() {
		return typeIdsOffset;
	}

	public int getTypeIdsSize() {
		return typeIdsSize;
	}

	public List<TypeIDItem> getTypes() {
		return Collections.unmodifiableList(types);
	}

	public int getProtoIdsOffset() {
		return protoIdsOffset;
	}

	public int getProtoIdsSize() {
		return protoIdsSize;
	}

	public List<PrototypesIDItem> getPrototypes() {
		return Collections.unmodifiableList(prototypes);
	}

	public int getLinkOffset() {
		return linkOffset;
	}

	public int getLinkSize() {
		return linkSize;
	}

	public int getMapOffset() {
		return mapOffset;
	}

	public MapList getMapList() {
		return mapList;
	}

	public Address getMethodAddress(Program program, int methodId) {
		if (methodId < 0 || methodId >= methodIdsSize) {
			return Address.NO_ADDRESS;
		}
		Address addr;
		synchronized (methodXref) {
			addr = methodXref.get(methodId);
			if (addr == null) { // First time we've tried to access address
				addr = DexUtil.toLookupAddress(program, methodId);		// Find "__lookup__" address
				int val;
				try {
					val = program.getMemory().getInt(addr);
					if (val != -1) {			// If there is an address here, it is in memory location of function
						addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(
							val & 0xffffffffL);
					}
					// Otherwise, the method is external, and we use the lookup address as placeholder
				}
				catch (MemoryAccessException e) {
					addr = Address.NO_ADDRESS;
				}
				methodXref.put(methodId, addr);
			}
		}
		return addr;
	}

	public DataType getDataType(Program program, short typeShort) {
		int typeId = typeShort & 0xffff;
		if (typeId < 0 || typeId >= typeIdsSize) {
			return null;
		}
		DataType res;
		synchronized (typeXref) {
			res = typeXref.get(typeId);
			if (res == null) {
				TypeIDItem typeIDItem = types.get(typeId);
				String typeString = DexUtil.convertToString(this, typeIDItem.getDescriptorIndex());
				if (typeString.length() != 0 && typeString.charAt(0) == 'L') {
					StringBuilder buffer = new StringBuilder();
					buffer.append(DexUtil.HANDLE_PATH);
					buffer.append("group").append(typeId / 100);
					buffer.append(CategoryPath.DELIMITER_CHAR);
					buffer.append("type").append(typeId);
					DataType handleType =
						program.getDataTypeManager().getDataType(buffer.toString());
					if (handleType instanceof TypeDef) {
						res = new PointerDataType(((TypeDef) handleType).getDataType(),
							program.getDataTypeManager());
					}
				}
				if (res == null) {
					res = DexUtil.toDataType(program.getDataTypeManager(), typeString);
				}
				if (res != null) {
					typeXref.put(typeId, res);
				}
			}
		}
		return res;
	}
}
