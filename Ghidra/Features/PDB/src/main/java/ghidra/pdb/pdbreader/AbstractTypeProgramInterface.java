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
package ghidra.pdb.pdbreader;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.msfreader.MsfStream;
import ghidra.pdb.pdbreader.type.AbstractMsType;
import ghidra.pdb.pdbreader.type.PrimitiveMsType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Type Program Interface component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public abstract class AbstractTypeProgramInterface {

	public static final int STREAM_NUMBER_SIZE = 2;

	protected static final int VERSION_NUMBER_SIZE = 4;
	protected static final int HEADER_LENGTH_SIZE = 4;
	protected static final int TYPE_INDEX_SIZE = 4;
	protected static final int TYPE_INDEX16_SIZE = 2;
	protected static final int DATA_LENGTH_SIZE = 4;

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected AbstractPdb pdb;
	private int streamNumber;

	protected int typeIndexMin;
	protected int typeIndexMaxExclusive;
	protected int dataLength;

	protected Map<Integer, PrimitiveMsType> primitivesMap = new HashMap<>();
	protected List<AbstractMsType> typeList = new ArrayList<>();

	protected int versionNumber = 0;

	//==============================================================================================
	protected CategoryIndex.Category category;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdbIn {@link AbstractPdb} that owns this {@link AbstractTypeProgramInterface}.
	 * @param streamNumber The stream number that contains the
	 *  {@link AbstractTypeProgramInterface} data.
	 */
	public AbstractTypeProgramInterface(AbstractPdb pdbIn, int streamNumber) {
		this.pdb = pdbIn;
		this.streamNumber = streamNumber;
	}

	/**
	 * Returns the number of bytes needed to store a {@link AbstractTypeProgramInterface}
	 *  version number.
	 * @return The number of bytes read from the bytes array.
	 */
	static int getVersionNumberSize() {
		return VERSION_NUMBER_SIZE;
	}

	/**
	 * Deserializes Version Number of the {@link AbstractTypeProgramInterface} from the
	 *  {@link PdbByteReader}.
	 * @param reader {@link PdbByteReader} from which to deserialize.
	 * @return Version number.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	static int deserializeVersionNumber(PdbByteReader reader) throws PdbException {
		return reader.parseInt();
	}

	/**
	 * Sets the active enum {@link CategoryIndex.Category} for the list that we are processing.
	 *  This is not a standard part of the PDB, but something we used for creation of a Dependency
	 * order/graph.  It is something we added (and might be removed in the future) as we have
	 * investigated how to analyze and apply the PDB.
	 * @param category enum {@link CategoryIndex.Category} to set.
	 */
	public void setCategory(CategoryIndex.Category category) {
		this.category = category;
	}

	/**
	 * Returns the TypeIndexMin.
	 * @return The TypeIndexMin value from the header.
	 */
	public int getTypeIndexMin() {
		return typeIndexMin;
	}

	/**
	 * Returns the TypeIndexMaxExclusive.
	 * @return TypeIndexMaxExclusive value from the header.
	 */
	public int getTypeIndexMaxExclusive() {
		return typeIndexMaxExclusive;
	}

	/**
	 * Retrieves the {@link AbstractMsType} record indicated by the recordNumber.  The record must
	 *  already have been parsed and inserted into the list.
	 * @param recordNumber Record number to look up.
	 * @return {@link AbstractMsType} pertaining to the record number.
	 */
	public AbstractMsType getRecord(int recordNumber) {
		if (recordNumber < typeIndexMin) {
			PrimitiveMsType primitive = primitivesMap.get(recordNumber);
			if (primitive == null) {
				primitive = new PrimitiveMsType(pdb, recordNumber);
				primitivesMap.put(recordNumber, primitive);
			}
			return primitive;
		}
		return typeList.get(recordNumber - typeIndexMin);
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Deserializes this {@link AbstractTypeProgramInterface}.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @return Version number of the {@link AbstractTypeProgramInterface}.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	int deserialize(TaskMonitor monitor) throws IOException, PdbException, CancelledException {
		if (pdb.getMsf() == null) {
			// Should only be null dummy PDBs used for testing.
			throw new PdbException("Unexpected null MSF.");
		}
		MsfStream stream = pdb.getMsf().getStream(streamNumber);
		byte[] bytes = stream.read(0, stream.getLength(), monitor);
		PdbByteReader reader = new PdbByteReader(bytes);

		deserializeHeader(reader);
		deserializeTypeRecords(reader);

		return versionNumber;
	}

	/**
	 * Dumps this class.  This package-protected method is for debugging only.
	 * @param writer {@link Writer} to which to write the debug dump.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	void dump(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("TypeProgramInterfaceHeader----------------------------------\n");
		builder.append(dumpHeader());
		builder.append("\nEnd TypeProgramInterfaceHeader------------------------------\n");
		builder.append("TypeProgramInterfaceRecords---------------------------------\n");
		builder.append(dumpTypeRecords());
		builder.append("\nEnd TypeProgramInterfaceRecords-----------------------------\n");
		writer.write(builder.toString());
	}

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a basic object.
	 *  Note: not all values are initialized.  This is a dummy constructor used to create a dummy
	 *  {@link AbstractTypeProgramInterface}.
	 *  Note: not all values of this class get initialized by this method.  
	 * @param pdb {@link AbstractPdb} that owns this this class.
	 * @param typeIndexMin The IndexMin to set/use.
	 * @param typeIndexMaxExclusive One greater than the MaxIndex to set/use.
	 */
	AbstractTypeProgramInterface(AbstractPdb pdb, int typeIndexMin, int typeIndexMaxExclusive) {
		this.pdb = pdb;
		this.typeIndexMin = typeIndexMin;
		this.typeIndexMaxExclusive = typeIndexMaxExclusive;
	}

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a record for a particular
	 *  record number.
	 * @param recordNumber Record number for the {@link AbstractMsType} to be inserted.
	 * @param type {@link AbstractMsType} to be inserted.
	 * @return True if successful.
	 */
	boolean setRecord(int recordNumber, AbstractMsType type) {
		if (recordNumber < typeIndexMin) {
			return false;
		}
		for (int i = typeList.size() + typeIndexMin; i <= recordNumber; i++) {
			// Add the same record for each index up to the one needed.
			typeList.add(type);
		}
		return true;
	}

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to add a record that gets its
	 *  record number automatically assigned.
	 * @param type {@link AbstractMsType} to be inserted.
	 * @return Record number assigned.
	 */
	int addRecord(AbstractMsType type) {
		int newRecordNum = typeList.size() + typeIndexMin;
		typeList.add(type);
		return newRecordNum;
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Deserializes the Header of this class.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void deserializeHeader(PdbByteReader reader) throws PdbException;

	/**
	 * Dumps the Header.  This method is for debugging only.
	 * @return {@link String} of pretty output.
	 */
	protected abstract String dumpHeader();

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Deserializes the Type Records of this class.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected void deserializeTypeRecords(PdbByteReader reader) throws PdbException {
		int recordLength;
		int recordNumber = typeIndexMin;
		TypeParser parser = pdb.getTypeParser();
		//System.out.println(reader.dump());
		while (reader.hasMore()) {
			int index = reader.getIndex();
			//System.out.println("index: " + index);
			//System.out.println("record: " + recordNumber);
			// The following code is for developmental investigations;
			//  set break point on "int a = 1;" instead of a
			//  conditional break point.
			if (index == 18) {
				int a = 1;
				a = a + 1;
			}
			// The following code is for developmental investigations;
			//  set break point on "int a = 1;" instead of a
			//  conditional break point.
			if (recordNumber == 4096) {
				int a = 1;
				a = a + 1;
			}
			recordLength = reader.parseUnsignedShortVal();
			PdbByteReader recordReader = reader.getSubPdbByteReader(recordLength);
			recordReader.markAlign(2);
			pdb.pushDependencyStack(new CategoryIndex(category, recordNumber));
			AbstractMsType type = parser.parse(recordReader);
			pdb.popDependencyStack();
			typeList.add(type);
			//System.out.println(type.getClass().getSimpleName());
			//System.out.println(type.toString());
			recordNumber++;
		}
		//assert (recordNumber == typeIndexMaxExclusive + 1); //not really TI + 1
	}

	//TODO: more to do for outputting individual records (might want a toString or dump method
	// on each).
	/**
	 * Dumps the Type Records.  This method is for debugging only.
	 * @return {@link String} of pretty output.
	 */
	protected String dumpTypeRecords() {
		StringBuilder builder = new StringBuilder();
		int recordNum = typeIndexMin;
		for (AbstractMsType type : typeList) {
			builder.append("------------------------------------------------------------\n");
			builder.append("Record: ");
			builder.append(recordNum);
			builder.append("\n");

			// The following code is for developmental investigations;
			//  set break point on "int a = 1;" instead of a
			//  conditional break point.
			if (recordNum == -2) {
				int a = 1;
				a = a + 1;
			}
			if (type != null) {
				builder.append(type.getClass().getSimpleName());
				builder.append("\n");
				builder.append(type.toString());
				builder.append("\n");
			}
			else {
				builder.append("(null)\n"); //Temporary output value.
			}
			recordNum++;
		}
		return builder.toString();
	}

}
