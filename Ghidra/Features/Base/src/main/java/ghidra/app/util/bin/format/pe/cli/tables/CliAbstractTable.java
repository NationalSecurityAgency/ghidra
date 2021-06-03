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
package ghidra.app.util.bin.format.pe.cli.tables;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PeMarkupable;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Generic Metadata table.  Subclasses should provided implementations for the actual
 * tables.
 */
public abstract class CliAbstractTable implements StructConverter, PeMarkupable {
	public static final String PATH = "/PE/CLI/Metadata/Tables";

	protected long readerOffset;

	protected CliTypeTable tableType;
	protected int numRows;
	protected ArrayList<CliAbstractTableRow> rows;

	protected CliStreamMetadata metadataStream;
	protected List<Integer> strings = new ArrayList<Integer>();
	protected List<Integer> blobs = new ArrayList<Integer>();
	protected List<Integer> userStrings = new ArrayList<Integer>();

	/**
	 * Creates a new generic CLI metadata table.  This is intended to be called by a subclass
	 * metadata table during its creation.
	 * 
	 * @param reader A reader that is used to read the table.
	 * @param metadataStream The metadata stream that the table lives in.
	 * @param tableType The type of table to create.
	 */
	public CliAbstractTable(BinaryReader reader, CliStreamMetadata metadataStream,
			CliTypeTable tableType) {
		this.readerOffset = reader.getPointerIndex();
		this.metadataStream = metadataStream;
		this.tableType = tableType;
		this.numRows = metadataStream.getNumberRowsForTable(tableType);
		this.rows = new ArrayList<>(this.numRows);
	}

	/**
	 * Gets this table's table type.
	 * 
	 * @return This table's table type.
	 */
	public CliTypeTable getTableType() {
		return tableType;
	}

	/**
	 * Gets the number of rows in this table.
	 * 
	 * return The number of rows in this table.
	 */
	public int getNumRows() {
		return numRows;
	}

	/**
	 * Gets the size in bytes of a row in this table.
	 * 
	 * return The size in bytes of a row in this table.
	 */
	public int getRowSize() {
		return getRowDataType().getLength();
	}

	/**
	 * Gets the size in bytes of this table.
	 * 
	 * @return The size in bytes of this table.
	 */
	public int getTableSize() {
		return getRowSize() * getNumRows();
	}

	/**
	 * Gets the row at the given index.
	 * <p>
	 * NOTE: Per ISO/IEC 23271:2012(E) III.1.9, Row indices start from 1, while heap/stream indices start from 0.
	 * 
	 * @param rowIndex The index of the row to get (starting at 1). 
	 * @return The row at the given index.
	 * @throws IndexOutOfBoundsException if the row index is invalid.
	 */
	public CliAbstractTableRow getRow(int rowIndex) throws IndexOutOfBoundsException {
		return rows.get(rowIndex - 1);
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor,
			MessageLog log, NTHeader ntHeader) throws DuplicateNameException,
			CodeUnitInsertionException, IOException, MemoryAccessException {
		// Markup is not required
	}

	/**
	 * Gets the data type of a row in this table.
	 * 
	 * @return The data type of a row in this table.
	 */
	public abstract DataType getRowDataType();

	@Override
	public DataType toDataType() {
		DataType rowDt = getRowDataType();
		int count = (numRows == 0) ? 1 : numRows;
		DataType array = new ArrayDataType(rowDt, count, rowDt.getLength());
		try {
			array.setCategoryPath(new CategoryPath(PATH));
		}
		catch (DuplicateNameException e) {
			Msg.warn(this, "Duplication category path: " + PATH);
		}
		return array;
	}


	@Override
	public String toString() {
		return tableType.toString();
	}

	/**
	 * Reads the blob index that the reader is positioned at.
	 * 
	 * @param reader A reader that is positioned at the blob index to read.
	 * @return The blob index that the reader is positioned at.
	 * @throws IOException if there is a problem reading the blob index.
	 */
	protected int readBlobIndex(BinaryReader reader) throws IOException {
		return metadataStream.getBlobIndexDataType() == DWordDataType.dataType
				? reader.readNextInt()
				: reader.readNextShort() & 0xffff;
	}

	/**
	 * Reads the string index that the reader is positioned at.
	 * 
	 * @param reader A reader that is positioned at the string index to read.
	 * @return The string index that the reader is positioned at.
	 * @throws IOException if there is a problem reading the string index.
	 */
	protected int readStringIndex(BinaryReader reader) throws IOException {
		return metadataStream.getStringIndexDataType() == DWordDataType.dataType
				? reader.readNextInt()
				: reader.readNextShort() & 0xffff;
	}

	/**
	 * Reads the GUID index that the reader is positioned at.
	 * 
	 * @param reader A reader that is positioned at the GUID index to read.
	 * @return The GUID index that the reader is positioned at.
	 * @throws IOException if there is a problem reading the GUID index.
	 */
	protected int readGuidIndex(BinaryReader reader) throws IOException {
		return metadataStream.getGuidIndexDataType() == DWordDataType.dataType
				? reader.readNextInt()
				: reader.readNextShort() & 0xffff;
	}

	/**
	 * Reads the table index that the reader is positioned at.
	 * 
	 * @param reader A reader that is positioned at the table index to read.
	 * @return The table index that the reader is positioned at.
	 * @throws IOException if there is a problem reading the table index.
	 */
	protected int readTableIndex(BinaryReader reader, CliTypeTable table) throws IOException {
		return metadataStream.getTableIndexDataType(table) == DWordDataType.dataType
				? reader.readNextInt()
				: reader.readNextShort() & 0xffff;
	}

	/**
	 * Convenience method for getting the row representation of a table.
	 * 
	 * @param table The table that has the row.
	 * @param index The index of the row.
	 * @return The row representation of a table.
	 */
	protected String getRowRepresentationSafe(CliTypeTable table, int index) {
		return metadataStream.getTable(table).getRow(index).getRepresentation();
	}

	/**
	 * Convenience method for getting a safe row representation of a table.
	 * 
	 * @param otherTable The table that has the row.
	 * @param index The index of the row.
	 * @return The safe row representation of a table.
	 */
	protected String getRowShortRepSafe(CliTypeTable otherTable, int index) {
		return metadataStream.getTable(otherTable).getRow(index).getShortRepresentation();
	}
}
