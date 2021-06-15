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
package ghidra.app.util.bin.format.pe.cli.streams;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeUtils;
import ghidra.app.util.bin.format.pe.cli.CliStreamHeader;
import ghidra.app.util.bin.format.pe.cli.tables.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * The Metadata stream is giant and complicated.  It is made up of {@link CliAbstractTable}s.
 *
 * @see CliTypeTable
 */
public class CliStreamMetadata extends CliAbstractStream {

	private byte majorVersion;
	private byte minorVersion;
	private byte heapSizes;
	private long valid;
	private long sorted;
	private HashMap<CliTypeTable, Integer> rows;
	private ArrayList<CliAbstractTable> tables = new ArrayList<>();

	private CliStreamGuid guidStream;
	private CliStreamUserStrings userStringsStream;
	private CliStreamStrings stringsStream;
	private CliStreamBlob blobStream;

	/**
	 * Gets the name of this stream.
	 *
	 * @return The name of this stream.
	 */
	public static String getName() {
		return "#~";
	}

	/**
	 * Creates a new Metadata stream.
	 *
	 * @param header The stream header associated with this stream.
	 * @param guidStream The GUID stream.
	 * @param userStringsStream The user strings stream.
	 * @param stringsStream The strings stream.
	 * @param blobStream The blob stream.
	 * @param fileOffset The file offset where this stream starts.
	 * @param rva The relative virtual address where this stream starts.
	 * @param reader A reader that is set to the start of the stream.
	 * @throws IOException if there is a problem reading the stream.
	 */
	public CliStreamMetadata(CliStreamHeader header, CliStreamGuid guidStream,
			CliStreamUserStrings userStringsStream, CliStreamStrings stringsStream,
			CliStreamBlob blobStream, long fileOffset, int rva, BinaryReader reader)
			throws IOException {
		super(header, fileOffset, rva, reader);

		this.rows = new HashMap<>();
		this.tables = new ArrayList<>();

		this.guidStream = guidStream;
		this.userStringsStream = userStringsStream;
		this.stringsStream = stringsStream;
		this.blobStream = blobStream;
	}

	@Override
	public boolean parse() throws IOException {
		reader.setPointerIndex(offset);

		reader.readNextInt(); // reserved
		majorVersion = reader.readNextByte();
		minorVersion = reader.readNextByte();
		heapSizes = reader.readNextByte();
		reader.readNextByte(); // reserved
		valid = reader.readNextLong();
		sorted = reader.readNextLong();

		// Next is an array of n 4-byte unsigned integers indicating the number of rows for each present table
		for (int i = 0; i < 64; i++) {
			if ((valid & (1L << i)) != 0) {
				CliTypeTable tableType = CliTypeTable.fromId(i);
				if (tableType != null) {
					rows.put(tableType, reader.readNextInt());
				}
				else {
					Msg.warn(this, "CLI metadata table with id " + i + " is not supported");
				}
			}
		}

		// Now the tables follow directly after
		for (int i = 0; i < 64; i++) {
			if ((valid & (1L << i)) != 0) {
				CliTypeTable tableType = CliTypeTable.fromId(i);
				if (tableType != null) {
					long origIndex = reader.getPointerIndex();
					CliAbstractTable table = createTableObject(tableType);
					tables.add(table);
					reader.setPointerIndex(origIndex + table.toDataType().getLength());
				}
			}
		}

		return true;
	}

	/**
	 * Gets the GUID stream.
	 *
	 * @return The GUID stream.  Could be null if one doesn't exist.
	 */
	public CliStreamGuid getGuidStream() {
		return guidStream;
	}

	/**
	 * Gets the user strings stream.
	 *
	 * @return The user strings stream.  Could be null if one doesn't exist.
	 */
	public CliStreamUserStrings getUserStringsStream() {
		return userStringsStream;
	}

	/**
	 * Gets the strings stream.
	 *
	 * @return The strings stream.  Could be null if one doesn't exist.
	 */
	public CliStreamStrings getStringsStream() {
		return stringsStream;
	}

	/**
	 * Gets the blob stream.
	 *
	 * @return The blob stream.  Could be null if one doesn't exist.
	 */
	public CliStreamBlob getBlobStream() {
		return blobStream;
	}

	/**
	 * Creates a new {@link CliAbstractTable} from the table at the current reader index
	 * with the given table type.
	 *
	 * @param tableType The type of table to create.
	 * @return A new table with the given type.  Could be null if we don't support the table type.
	 * @throws IOException if there was an issue reading the new table.
	 */
	private CliAbstractTable createTableObject(CliTypeTable tableType) throws IOException {
		switch (tableType) {
			case Module:
				return new CliTableModule(reader, this, tableType);

			case TypeRef:
				return new CliTableTypeRef(reader, this, tableType);

			case TypeDef:
				return new CliTableTypeDef(reader, this, tableType);

			case Field:
				return new CliTableField(reader, this, tableType);

			case MethodDef:
				return new CliTableMethodDef(reader, this, tableType);

			case Param:
				return new CliTableParam(reader, this, tableType);

			case InterfaceImpl:
				return new CliTableInterfaceImpl(reader, this, tableType);

			case MemberRef:
				return new CliTableMemberRef(reader, this, tableType);

			case Constant:
				return new CliTableConstant(reader, this, tableType);

			case CustomAttribute:
				return new CliTableCustomAttribute(reader, this, tableType);

			case FieldMarshal:
				return new CliTableFieldMarshall(reader, this, tableType);

			case DeclSecurity:
				return new CliTableDeclSecurity(reader, this, tableType);

			case ClassLayout:
				return new CliTableClassLayout(reader, this, tableType);

			case FieldLayout:
				return new CliTableFieldLayout(reader, this, tableType);

			case StandAloneSig:
				return new CliTableStandAloneSig(reader, this, tableType);

			case EventMap:
				return new CliTableEventMap(reader, this, tableType);

			case Event:
				return new CliTableEvent(reader, this, tableType);

			case PropertyMap:
				return new CliTablePropertyMap(reader, this, tableType);

			case Property:
				return new CliTableProperty(reader, this, tableType);

			case MethodSemantics:
				return new CliTableMethodSemantics(reader, this, tableType);

			case MethodImpl:
				return new CliTableMethodImpl(reader, this, tableType);

			case ModuleRef:
				return new CliTableModuleRef(reader, this, tableType);

			case TypeSpec:
				return new CliTableTypeSpec(reader, this, tableType);

			case ImplMap:
				return new CliTableImplMap(reader, this, tableType);

			case FieldRVA:
				return new CliTableFieldRVA(reader, this, tableType);

			case Assembly:
				return new CliTableAssembly(reader, this, tableType);

			case AssemblyProcessor:
				return new CliTableAssemblyProcessor(reader, this, tableType);

			case AssemblyOS:
				return new CliTableAssemblyOS(reader, this, tableType);

			case AssemblyRef:
				return new CliTableAssemblyRef(reader, this, tableType);

			case AssemblyRefProcessor:
				return new CliTableAssemblyRefProcessor(reader, this, tableType);

			case AssemblyRefOS:
				return new CliTableAssemblyRefOS(reader, this, tableType);

			case File:
				return new CliTableFile(reader, this, tableType);

			case ExportedType:
				return new CliTableExportedType(reader, this, tableType);

			case ManifestResource:
				return new CliTableManifestResource(reader, this, tableType);

			case NestedClass:
				return new CliTableNestedClass(reader, this, tableType);

			case GenericParam:
				return new CliTableGenericParam(reader, this, tableType);

			case MethodSpec:
				return new CliTableMethodSpec(reader, this, tableType);

			case GenericParamConstraint:
				return new CliTableGenericParamConstraint(reader, this, tableType);

			default:
				Msg.warn(this,
					"Parsing table type \"" + tableType.toString() + "\" is not supported.");
				return null;
		}
	}

	/**
	 * Gets the major version.
	 *
	 * @return The major version.
	 */
	public short getMajorVersion() {
		return majorVersion;
	}

	/**
	 * Gets the minor version.
	 *
	 * @return The minor version.
	 */
	public short getMinorVersion() {
		return minorVersion;
	}

	/**
	 * Gets the sorted field.
	 *
	 * @return The sorted field.
	 */
	public long getSorted() {
		return sorted;
	}

	/**
	 * Gets the valid field.
	 *
	 * @return The valid field.
	 */
	public long getValid() {
		return valid;
	}

	/**
	 * Gets the table with the provided table type from the metadata stream.
	 *
	 * @param tableType The type of table to get.
	 * @return The table with the provided table type.  Could be null if it doesn't exist.
	 */
	public CliAbstractTable getTable(CliTypeTable tableType) {
		// Make sure it is present
		if (!isTablePresent(tableType)) {
			return null;
		}

		// Get the already-created table
		int tableIndex = getPresentTableIndex(tableType);
		if (tableIndex < tables.size()) {
			CliAbstractTable tableObj = tables.get(tableIndex);
			if (tableObj.getTableType() == tableType) {
				return tableObj;
			}
		}

		return null;
	}

	/**
	 * Gets the table with the provided table type id from the metadata stream.
	 *
	 * @param tableId The id of the table type to get.
	 * @return The table with the provided table id.  Could be null if it doesn't exist.
	 */
	public CliAbstractTable getTable(int tableId) {
		return getTable(CliTypeTable.fromId(tableId));
	}

	/**
	 * Gets the number of rows in the table with the given table type.
	 *
	 * @param tableType The type of table to get the number of rows of.
	 * @return The number of rows in the table with the given table type.  Could be 0 if
	 *   the table of the given type was not found.
	 */
	public int getNumberRowsForTable(CliTypeTable tableType) {
		Integer ret = rows.get(tableType);
		return (ret != null) ? ret : 0;
	}

	/**
	 * Gets the data type of the index into the string stream.  Will be either
	 * {@link DWordDataType} or {@link WordDataType}.
	 *
	 * @return The data type of the index into the string stream.
	 */
	public DataType getStringIndexDataType() {
		return ((heapSizes & 0x01) != 0) ? DWordDataType.dataType : WordDataType.dataType;
	}

	/**
	 * Gets the data type of the index into the GUID stream.  Will be either
	 * {@link DWordDataType} or {@link WordDataType}.
	 *
	 * @return The data type of the index into the string stream.
	 */
	public DataType getGuidIndexDataType() {
		return ((heapSizes & 0x02) != 0) ? DWordDataType.dataType : WordDataType.dataType;
	}

	/**
	 * Gets the data type of the index into the Blob stream.  Will be either
	 * {@link DWordDataType} or {@link WordDataType}.
	 *
	 * @return The data type of the index into the string stream.
	 */
	public DataType getBlobIndexDataType() {
		return ((heapSizes & 0x04) != 0) ? DWordDataType.dataType : WordDataType.dataType;
	}

	/**
	 * Gets the data type of the index into a metadata table.  Will be either
	 * {@link DWordDataType} or {@link WordDataType}.
	 *
	 * @return The data type of the index into the string stream.
	 */
	public DataType getTableIndexDataType(CliTypeTable table) {
		return (getNumberRowsForTable(table) >= (1 << 16)) ? DWordDataType.dataType
				: WordDataType.dataType;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, IOException {
		super.markup(program, isBinary, monitor, log, ntHeader);
		for (CliAbstractTable table : tables) {
			try {
				Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader,
					rva + getTableOffset(table.getTableType()));
				program.getBookmarkManager()
						.setBookmark(addr, BookmarkType.INFO, "CLI Table", table.toString());

				table.markup(program, isBinary, monitor, log, ntHeader);
			}
			catch (Exception e) {
				Msg.error(this, "Failed to markup " + table + ": " + e.getMessage());
			}
		}
	}

	@Override
	public DataType toDataType() {
		Structure struct = new StructureDataType(new CategoryPath(PATH), header.getName(), 0);
		struct.add(DWORD, "Reserved", "Always 0");
		struct.add(BYTE, "MajorVersion", null);
		struct.add(BYTE, "MinorVersion", null);
		struct.add(BYTE, "HeapSizes", "Bit vector for heap sizes");
		struct.add(BYTE, "Reserved", "Always 1");
		struct.add(QWORD, "Valid", "Bit vector of present tables");
		struct.add(QWORD, "Sorted", "Bit vector of sorted tables");
		struct.add(new ArrayDataType(DWORD, Long.bitCount(valid), DWORD.getLength()), "Rows",
			"# of rows for each corresponding present table");
		for (CliAbstractTable table : tables) {
			struct.add(table.toDataType(), table.toString(),
				"CLI Metadata Table: " + table.toString());
		}
		return struct;
	}

	private boolean isTablePresent(CliTypeTable tableType) {
		return ((valid & (1L << tableType.id())) != 0);
	}

	private int getTableOffset(CliTypeTable table) {
		StructureDataType struct = (StructureDataType) this.toDataType();
		int structOffset = 8; // Struct offset (0-indexed) of first metadata table
		structOffset += getPresentTableIndex(table);
		return struct.getComponent(structOffset).getOffset();
	}

	private int getPresentTableIndex(CliTypeTable table) {
		int tableId = table.id();
		long mask = valid & ((1L << tableId) - 1); // mask tables that come after this one. Start with all present tables, 0 out any that are after tableId.
		int tablesBefore = Long.bitCount(mask);
		return tablesBefore;
	}
}
