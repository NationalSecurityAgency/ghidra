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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Public Symbol Information component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 *   @see AbstractSymbolInformation
 *   @see GlobalSymbolInformation
 */
public class PublicSymbolInformation extends AbstractSymbolInformation {

	//==============================================================================================
	// Internals
	//==============================================================================================
	private int symbolHashLength;
	private int addressMapLength;
	private int numThunks; // unsigned int
	private int thunkSize;
	private int iSectionThunkTable; // unsigned short
	private int offsetThunkTable;
	private int numSections; // unsigned int
	private int thunkMapLength;
	private int thunkTableLength;
	private int sectionMapLength;

	// These should correspond with symbolOffsets that come from HashRecords.
	private List<Long> addressMapSymbolOffsets = new ArrayList<>();
	private Map<Integer, Integer> thunkTargetOffsetsByTableOffset = new HashMap<>();
	private Map<Integer, Integer> absoluteOffsetsBySectionNumber = new HashMap<>();

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdbIn {@link AbstractPdb} that owns the Public Symbol Information to process.
	 */
	public PublicSymbolInformation(AbstractPdb pdbIn) {
		super(pdbIn);
	}

	/**
	 * Returns the number of thunks in the thunk table.
	 * @return the number of thunks.
	 */
	public int getNumThunks() {
		return numThunks;
	}

	/**
	 * Returns the section within which the thunk table is located. 
	 * @return the section of the thunk table.
	 */
	public int getThunkTableSection() {
		return iSectionThunkTable;
	}

	/**
	 * Returns the offset of the thunk table within the section it is located. 
	 * @return the offset of the thunk table.
	 */
	public int getThunkTableOffset() {
		return offsetThunkTable;
	}

	/**
	 * Returns the size of each thunk in the thunk table.
	 * @return the size of a thunk.
	 */
	public int getThunkSize() {
		return thunkSize;
	}

	/**
	 * Returns the overall length of the thunk table.
	 * @return the thunk table length.
	 */
	public int getThunkTableLength() {
		return thunkTableLength;
	}

	/**
	 * Returns the number of sections recorded for the program.
	 * @return the number of sections.
	 */
	public int getNumSections() {
		return numSections;
	}

	/**
	 * Returns the Offsets of symbols within the symbol table gotten from the address map.  These
	 *  offsets to point to the size field of the symbols in the symbol table.
	 * @return offsets
	 */
	public List<Long> getAddressMapSymbolOffsets() {
		return addressMapSymbolOffsets;
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Deserialize the {@link PublicSymbolInformation} from the appropriate stream in the Pdb.
	 * @param streamNumber the stream number containing the information to deserialize.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	@Override
	void deserialize(int streamNumber, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		super.deserialize(streamNumber, monitor);

		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, monitor);

		deserializePubHeader(reader);

		PdbByteReader hashReader = reader.getSubPdbByteReader(symbolHashLength);
		deserializeHashTable(hashReader, monitor);

		PdbByteReader addressMapReader = reader.getSubPdbByteReader(addressMapLength);
		deserializeAddressMap(addressMapReader, monitor);

		PdbByteReader thunkMapReader = reader.getSubPdbByteReader(thunkMapLength);
		deserializeThunkMap(thunkMapReader, monitor);

		/*
		 * See note in {@link #deserializePubHeader(PdbByteReader)} regarding spurious data
		 * for numSections.  Because of this, we will assume the rest of the data in the
		 * reader belongs to the section map and set the appropriate variable values here.
		 */
		sectionMapLength = reader.numRemaining();
		if (sectionMapLength % 8 != 0) {
			throw new PdbException("sectionMapLength size not multiple of 8");
		}
		numSections = sectionMapLength / 8;
		PdbByteReader sectionMapReader = reader.getSubPdbByteReader(sectionMapLength);
		deserializeSectionMap(sectionMapReader, monitor);

		// Organize the information
		generateSymbolsList(monitor);
	}

	/**
	 * Debug method for dumping information from this {@link PublicSymbolInformation}.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	@Override
	void dump(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("PublicSymbolInformation-------------------------------------\n");
		dumpPubHeader(builder);
		dumpHashHeader(builder);
		dumpHashBasics(builder);
		dumpHashRecords(builder);

		dumpAddressMap(builder);
		dumpThunkMap(builder);
		dumpSectionMap(builder);

		builder.append("\nEnd PublicSymbolInformation---------------------------------\n");
		writer.write(builder.toString());
	}

	//==============================================================================================
	// Private Internals
	//==============================================================================================
	/**
	 * Deserializes the Address Map for these public symbols.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	private void deserializeAddressMap(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		while (reader.hasMore()) {
			monitor.checkCanceled();
			addressMapSymbolOffsets.add((long) reader.parseInt());
		}
	}

	/**
	 * Debug method for dumping Address Map information from this {@link AbstractSymbolInformation}.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	private void dumpAddressMap(StringBuilder builder) {
		builder.append("AddressMapSymbolOffsets-------------------------------------\n");
		builder.append("numAddressMapSymbolOffsets: " + addressMapSymbolOffsets.size() + "\n");
		int num = 0;
		for (Long val : addressMapSymbolOffsets) {
			builder.append(String.format("0X%08X: 0X%012X\n", num++, val));
		}
		builder.append("\nEnd AddressMapSymbolOffsets---------------------------------\n");
	}

	/**
	 * Deserializes the Thunk Map for these public symbols.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	private void deserializeThunkMap(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		int count = 0;
		while (reader.hasMore()) {
			monitor.checkCanceled();
			int targetOffset = reader.parseInt();
			int mapTableOffset = count * thunkSize + offsetThunkTable;
			thunkTargetOffsetsByTableOffset.put(mapTableOffset, targetOffset);
		}
	}

	/**
	 * Debug method for dumping Thunk Map information from this {@link AbstractSymbolInformation}.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	private void dumpThunkMap(StringBuilder builder) {
		builder.append("ThunkMap----------------------------------------------------\n");
		builder.append(
			"numThunkTargetOffsetsByTableOffset: " + thunkTargetOffsetsByTableOffset.size() + "\n");
		for (Map.Entry<Integer, Integer> entry : thunkTargetOffsetsByTableOffset.entrySet()) {
			builder.append(String.format("0X%08X  0X%08X\n", entry.getKey(), entry.getValue()));
		}
		builder.append("\nEnd ThunkMap------------------------------------------------\n");
	}

	/**
	 * Deserializes the Section Map for these public symbols.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	private void deserializeSectionMap(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		while (reader.hasMore()) {
			monitor.checkCanceled();
			int offset = reader.parseInt();
			int section = reader.parseUnsignedShortVal();
			reader.skip(2); // padding
			absoluteOffsetsBySectionNumber.put(section, offset);
		}
	}

	/**
	 * Debug method for dumping Section Map information from this {@link AbstractSymbolInformation}.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	private void dumpSectionMap(StringBuilder builder) {
		builder.append("SectionMap--------------------------------------------------\n");
		builder.append(
			"numAbsoluteOffsetsBySectionNumber: " + absoluteOffsetsBySectionNumber.size() + "\n");
		for (Map.Entry<Integer, Integer> entry : absoluteOffsetsBySectionNumber.entrySet()) {
			builder.append(String.format("0X%08X  0X%08X\n", entry.getKey(), entry.getValue()));
		}
		builder.append("\nEnd SectionMap----------------------------------------------\n");
	}

	/**
	 * Debug method for dumping the {@link PublicSymbolInformation} header.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	private void dumpPubHeader(StringBuilder builder) {
		builder.append("PublicSymbolInformationHeader-------------------------------\n");
		builder.append("symbolHashLength: ");
		builder.append(symbolHashLength);
		builder.append("\naddressMapLength: ");
		builder.append(addressMapLength);
		builder.append("\nnumThunks: ");
		builder.append(numThunks);
		builder.append("\nthunkSize: ");
		builder.append(thunkSize);
		builder.append("\niSectionThunkTable: ");
		builder.append(iSectionThunkTable);
		builder.append("\noffsetThunkTable: ");
		builder.append(offsetThunkTable);
		builder.append("\nnumSections: ");
		builder.append(numSections);
		builder.append("\nthunkMapLength: ");
		builder.append(thunkMapLength);
		builder.append("\nthunkTableLength: ");
		builder.append(thunkTableLength);
		builder.append("\nEnd PublicSymbolInformationHeader---------------------------\n");
	}

	// Issue: MSFT does not initialize PSGSIHDR with nSects(0) (our numSections), so spurious
	// data can be seen for this field.  We cannot do sanity checks on the value.  The only
	// effective thing we can do is to check if any data is left in the reader.  Whatever amount
	// is left is what we will use.
	private void deserializePubHeader(PdbByteReader reader) throws PdbException {
		symbolHashLength = reader.parseInt();
		addressMapLength = reader.parseInt();
		long val = reader.parseUnsignedIntVal();
		if (val > Integer.MAX_VALUE) {
			throw new PdbException("Cannot support large unsigned integer num thunks");
		}
		numThunks = (int) val;
		thunkSize = reader.parseInt();
		iSectionThunkTable = reader.parseUnsignedShortVal();
		reader.skip(2); // padding
		offsetThunkTable = reader.parseInt();
		val = reader.parseUnsignedIntVal();
		// See note above regarding MSFT numSections issue
		//if (val > Integer.MAX_VALUE) {
		//	throw new PdbException("Cannot support large unsigned integer num sections");
		//}
		numSections = (int) val;

		// Calculated values.
		/*
		 * We should calculate and store these as long values, but
		 * {@link #PdbByteReader.getSubPdbByteReader(int)} does not support long, so we are
		 *  checking here and throwing exception if we cannot support it.
		 */
		val = 4 * numThunks;
		if (val > Integer.MAX_VALUE) {
			throw new PdbException("Cannot support large unsigned integer for thunk map length");
		}
		thunkMapLength = (int) val;
		val = thunkSize * numThunks;
		if (val > Integer.MAX_VALUE) {
			throw new PdbException("Cannot support large unsigned integer for thunk table length");
		}
		thunkTableLength = (int) val;
		// See note above regarding MSFT numSections issue
		//val = 8 * numSections;
		//if (val > Integer.MAX_VALUE) {
		//	throw new PdbException("Cannot support long value for section map length");
		//}
		//sectionMapLength = (int) val;
	}

}
