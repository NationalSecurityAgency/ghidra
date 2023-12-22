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

import ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfStream;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

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

	public static final int PUB_HEADER_SIZE = 28;

	//==============================================================================================
	// Internals
	//==============================================================================================
	private int addressMapLength;
	private int numThunks; // unsigned int
	private int thunkSize;
	private int iSectionThunkTable; // unsigned short
	private int offsetThunkTable;
	private int numSections; // unsigned int
	private int thunkMapLength;
	private int thunkTableLength;
	private int sectionMapLength;

	private int addressMapOffset;
	private int thunkMapOffset;
	private int sectionMapOffset;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor
	 * @param pdbIn {@link AbstractPdb} that owns the Public Symbol Information to process
	 * @param streamNumber the stream number containing the symbol information
	 */
	public PublicSymbolInformation(AbstractPdb pdbIn, int streamNumber) {
		super(pdbIn, streamNumber);
	}

	/**
	 * Returns the number of thunks in the thunk table
	 * @return the number of thunks
	 */
	public int getNumThunks() {
		return numThunks;
	}

	/**
	 * Returns the section within which the thunk table is located
	 * @return the section of the thunk table
	 */
	public int getThunkTableSection() {
		return iSectionThunkTable;
	}

	/**
	 * Returns the offset of the thunk table within the section it is located
	 * @return the offset of the thunk table
	 */
	public int getThunkTableOffset() {
		return offsetThunkTable;
	}

	/**
	 * Returns the size of each thunk in the thunk table
	 * @return the size of a thunk
	 */
	public int getThunkSize() {
		return thunkSize;
	}

	/**
	 * Returns the overall length of the thunk table
	 * @return the thunk table length
	 */
	public int getThunkTableLength() {
		return thunkTableLength;
	}

	/**
	 * Returns the number of sections recorded for the program
	 * @return the number of sections
	 */
	public int getNumSections() {
		return numSections;
	}

	/**
	 * Returns the Offsets of symbols within the symbol table gotten from the address map.  These
	 *  offsets to point to the size field of the symbols in the symbol table
	 * @return offsets
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	public List<Long> getAddressMapSymbolOffsets() throws CancelledException, PdbException {
		try {
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(streamNumber, addressMapOffset, addressMapLength);
			return deserializeAddressMap(reader);
		}
		catch (IOException e) {
			Msg.error(this, String.format(
				"PDB: Error creating address map symbol offsets while reading stream %d at offset %d and length %d",
				streamNumber, addressMapOffset, addressMapLength));
			return new ArrayList<>();
		}
	}

	/**
	 * Returns the Thunk Target Offsets by Table Offset
	 * @return the map
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	public Map<Integer, Integer> getThunkTargetOffsetsByTableOffset()
			throws CancelledException, PdbException {
		try {
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(streamNumber, thunkMapOffset, thunkMapLength);
			return deserializeThunkMap(reader);
		}
		catch (IOException e) {
			Msg.error(this, String.format(
				"PDB: Error creating thunk target offsets by table offset while reading stream %d offset %d and length %d",
				streamNumber, thunkMapOffset, thunkMapLength));
			return new HashMap<>();
		}
	}

	/**
	 * Returns the Absolute Offsets by Section Number map
	 * @return the map
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	public Map<Integer, Integer> getAbsoluteOffsetsBySectionNumber()
			throws CancelledException, PdbException {
		try {
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(streamNumber, sectionMapOffset, sectionMapLength);
			return deserializeSectionMap(reader);
		}
		catch (IOException e) {
			Msg.error(this, String.format(
				"PDB: Error creating absolute offsets by section number while reading stream %d offset %d and length %d",
				streamNumber, sectionMapOffset, sectionMapLength));
			return new HashMap<>();
		}
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Deserializes and intializes {@link PublicSymbolInformation} basic information from the
	 * appropriate stream in the Pdb so that later queries can be made
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	@Override
	void initialize() throws IOException, PdbException, CancelledException {
		initializeValues();
		deserializePubHeader();
		deserializeHashHeader();
	}

	/**
	 * Debug method for dumping information from this {@link PublicSymbolInformation}
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException issue reading PDBor upon issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	@Override
	void dump(Writer writer) throws IOException, CancelledException, PdbException {
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
	 * Deserializes the Address Map for these public symbols
	 * @param reader {@link PdbByteReader} containing the data buffer to process
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	private List<Long> deserializeAddressMap(PdbByteReader reader)
			throws PdbException, CancelledException {
		List<Long> myAddressMapSymbolOffsets = new ArrayList<>();
		while (reader.hasMore()) {
			pdb.checkCancelled();
			myAddressMapSymbolOffsets.add((long) reader.parseInt());
		}
		return myAddressMapSymbolOffsets;
	}

	/**
	 * Debug method for dumping Address Map information from this {@link AbstractSymbolInformation}
	 * @param builder {@link StringBuilder} to which to dump the information
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	private void dumpAddressMap(StringBuilder builder)
			throws CancelledException, IOException, PdbException {
		builder.append("AddressMapSymbolOffsets-------------------------------------\n");
		List<Long> myAddressMapSymbolOffsets = getAddressMapSymbolOffsets();
		builder.append("numAddressMapSymbolOffsets: " + myAddressMapSymbolOffsets.size() + "\n");
		int num = 0;
		for (Long val : myAddressMapSymbolOffsets) {
			pdb.checkCancelled();
			builder.append(String.format("0X%08X: 0X%012X\n", num++, val));
		}
		builder.append("\nEnd AddressMapSymbolOffsets---------------------------------\n");
	}

	/**
	 * Deserializes the Thunk Map for these public symbols
	 * @param reader {@link PdbByteReader} containing the data buffer to process
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	private Map<Integer, Integer> deserializeThunkMap(PdbByteReader reader)
			throws PdbException, CancelledException {
		int count = 0;
		Map<Integer, Integer> myThunkTargetOffsetsByTableOffset = new HashMap<>();
		while (reader.hasMore()) {
			pdb.checkCancelled();
			int targetOffset = reader.parseInt();
			int mapTableOffset = count * thunkSize + offsetThunkTable;
			myThunkTargetOffsetsByTableOffset.put(mapTableOffset, targetOffset);
		}
		return myThunkTargetOffsetsByTableOffset;
	}

	/**
	 * Debug method for dumping Thunk Map information from this {@link AbstractSymbolInformation}
	 * @param builder {@link StringBuilder} to which to dump the information
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	private void dumpThunkMap(StringBuilder builder)
			throws CancelledException, IOException, PdbException {
		Map<Integer, Integer> myThunkTargetOffsetsByTableOffset =
			getThunkTargetOffsetsByTableOffset();
		builder.append("ThunkMap----------------------------------------------------\n");
		builder.append("numThunkTargetOffsetsByTableOffset: " +
			myThunkTargetOffsetsByTableOffset.size() + "\n");
		for (Map.Entry<Integer, Integer> entry : myThunkTargetOffsetsByTableOffset.entrySet()) {
			pdb.checkCancelled();
			builder.append(String.format("0X%08X  0X%08X\n", entry.getKey(), entry.getValue()));
		}
		builder.append("\nEnd ThunkMap------------------------------------------------\n");
	}

	/**
	 * Deserializes the Section Map for these public symbols
	 * @param reader {@link PdbByteReader} containing the data buffer to process
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	private Map<Integer, Integer> deserializeSectionMap(PdbByteReader reader)
			throws PdbException, CancelledException {
		Map<Integer, Integer> myAbsoluteOffsetsBySectionNumber = new HashMap<>();
		while (reader.hasMore()) {
			pdb.checkCancelled();
			int offset = reader.parseInt();
			int section = reader.parseUnsignedShortVal();
			reader.skip(2); // padding
			myAbsoluteOffsetsBySectionNumber.put(section, offset);
		}
		return myAbsoluteOffsetsBySectionNumber;
	}

	/**
	 * Debug method for dumping Section Map information from this {@link AbstractSymbolInformation}
	 * @param builder {@link StringBuilder} to which to dump the information
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	private void dumpSectionMap(StringBuilder builder)
			throws CancelledException, IOException, PdbException {
		Map<Integer, Integer> myAbsoluteOffsetsBySectionNumber =
			getAbsoluteOffsetsBySectionNumber();
		builder.append("SectionMap--------------------------------------------------\n");
		builder.append(
			"numAbsoluteOffsetsBySectionNumber: " + myAbsoluteOffsetsBySectionNumber.size() + "\n");
		for (Map.Entry<Integer, Integer> entry : myAbsoluteOffsetsBySectionNumber.entrySet()) {
			pdb.checkCancelled();
			builder.append(String.format("0X%08X  0X%08X\n", entry.getKey(), entry.getValue()));
		}
		builder.append("\nEnd SectionMap----------------------------------------------\n");
	}

	/**
	 * Debug method for dumping the {@link PublicSymbolInformation} header
	 * @param builder {@link StringBuilder} to which to dump the information
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

	void deserializePubHeader() throws PdbException, CancelledException, IOException {
		MsfStream stream = pdb.getMsf().getStream(streamNumber);
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, 0, PUB_HEADER_SIZE);
		deserializePubHeader(reader, stream.getLength());
	}

	// Issue: MSFT does not initialize PSGSIHDR with nSects(0) (our numSections), so spurious
	// data can be seen for this field.  We cannot do sanity checks on the value.  The only
	// effective thing we can do is to check if any data is left in the reader.  Whatever amount
	// is left is what we will use.
	private void deserializePubHeader(PdbByteReader reader, int streamLength) throws PdbException {
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

		// Do some additional calculations
		symbolHashOffset = PUB_HEADER_SIZE; // reader.getIndex();
		addressMapOffset = symbolHashOffset + symbolHashLength;
		thunkMapOffset = addressMapOffset + addressMapLength;
		sectionMapOffset = thunkMapOffset + thunkMapLength;
		// Due to the possibility of spurious data for sections (noted above), we will assume
		//  the rest of the data belongs to the section map and set the appropriate variable
		//  values here.
		sectionMapLength = streamLength - sectionMapOffset;
		if (sectionMapLength % 8 != 0) {
			throw new PdbException("sectionMapLength size not multiple of 8");
		}
		numSections = sectionMapLength / 8;

	}

}
