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
import ghidra.pdb.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Global Symbol Information component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public class GlobalSymbolInformation {

	public static final int HEADER_SIGNATURE = 0xffffffff;

	public static final int GSI70 = 0xeffe0000 + 19990810; // 0xf12f091a = -248575718

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected AbstractPdb pdb;
	protected int numHashRecords;
	protected int numExtraBytes;
	protected int hashRecordsBitMapLength;

	private int headerSignature;
	private int versionNumber;
	private int hashRecordsLength;
	private int bucketsLength;

	//These belong to public symbols
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

	// These are read from "buckets."
	List<Integer> hashBucketOffsets = new ArrayList<>();
	Set<SymbolHashRecord> hashRecords = new TreeSet<>();
	List<Integer> symbolOffsets = new ArrayList<>();
	Map<Integer, Integer> mapTableOffsetToTargetOffset = new HashMap<>();
	Map<Integer, Integer> sectionNumToAbsoluteOffset = new HashMap<>();

	List<AbstractMsSymbol> symbols = new ArrayList<>();

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdbIn {@link AbstractPdb} that owns the Global Symbol Information to process.
	 */
	public GlobalSymbolInformation(AbstractPdb pdbIn) {
		pdb = pdbIn;
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
	 * Returns the list of symbols for this {@link GlobalSymbolInformation}.
	 * @return the symbols.
	 */
	public List<AbstractMsSymbol> getSymbols() {
		return symbols;
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	// NOTE 20190603: Plan is to refactor this class into two classes plus one abstract class:
	//  Global and Public to be separated (see boolean pub below for now), but need to investigate
	//  how individual modules might make use of this class or split class before making the final
	//  decision... so in other words, this is still under investigation for this as of the time
	//  of this submission for review, but need to move forward with what I currently have for now.
	/**
	 * Deserialize the {@link GlobalSymbolInformation} from the appropriate stream in the Pdb.
	 * @param streamNumber the stream number containing the information to deserialize.
	 * @param pub {@code true} if Public symbol information vs. Global symbol information.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	void deserialize(int streamNumber, boolean pub, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		if (pdb.minimalDebugInfo) {
			hashRecordsBitMapLength = 0x8000;
			numExtraBytes = 0; // I believe;
			numHashRecords = 0x3ffff;
		}
		else {
			hashRecordsBitMapLength = 0x200;
			numExtraBytes = 4;
			numHashRecords = 0x1000;
		}

		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, monitor);

		if (pub) {
			deserializePubHeader(reader);

			PdbByteReader hashReader = reader.getSubPdbByteReader(symbolHashLength);
			deserializeHashTable(hashReader, monitor);

			PdbByteReader addressMapReader = reader.getSubPdbByteReader(addressMapLength);
			deserializeAddressMap(addressMapReader, monitor);

			PdbByteReader thunkMapReader = reader.getSubPdbByteReader(thunkMapLength);
			deserializeThunkMap(thunkMapReader, monitor);

			/**
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
		}
		else {
			deserializeHashTable(reader, monitor);
		}

		// Organize the information
		generateSymbolsList(monitor);
	}

	/**
	 * Debug method for dumping information from this {@link GlobalSymbolInformation} header.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	protected void dumpHeader(StringBuilder builder) {
		builder.append("GlobalSymbolInformationHeader-------------------------------\n");
		builder.append("headerSignature: ");
		builder.append(headerSignature);
		builder.append("\nversionNumber: ");
		builder.append(versionNumber);
		builder.append("\nlengthHashRecords: ");
		builder.append(hashRecordsLength);
		builder.append("\nlengthBuckets: ");
		builder.append(bucketsLength);
		builder.append("\n End GlobalSymbolInformationHeader--------------------------\n");
	}

	/**
	 * Debug method for dumping hash records from this {@link GlobalSymbolInformation}.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	void dumpHashRecords(StringBuilder builder) {
		builder.append("HashRecords-------------------------------------------------\n");
		builder.append("numHashRecords: " + hashRecords.size());
		for (SymbolHashRecord record : hashRecords) {
			builder.append(
				String.format("0X%08X  0X%04X", record.getOffset(), record.getReferenceCount()));
		}
		builder.append("\n End HashRecords--------------------------------------------\n");
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
			symbolOffsets.add(reader.parseInt());
		}
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
			mapTableOffsetToTargetOffset.put(mapTableOffset, targetOffset);
		}
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
			sectionNumToAbsoluteOffset.put(section, offset);
		}
	}

	/**
	 * Deserializes the hash table for the symbols.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	private void deserializeHashTable(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {

		deserializeHashHeader(reader);

		if (headerSignature == HEADER_SIGNATURE) {
			switch (versionNumber) {
				case GSI70:
					deserializeGsi70HashTable(reader, monitor);
					break;
				default:
					throw new PdbException("Unknown GSI Version Number");
			}
		}
		else {
			reader.reset(); // There was no header
			deserializeGsiPre70HashTable(reader, monitor);
		}

	}

	/**
	 * Deserialize the header of the Hash from the {@link PdbByteReader} provided.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	private void deserializeHashHeader(PdbByteReader reader) throws PdbException {
		headerSignature = reader.parseInt();
		versionNumber = reader.parseInt();
		hashRecordsLength = reader.parseInt();
		bucketsLength = reader.parseInt();
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
		/**
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

	/**
	 * Deserialize the body of the {@link GlobalSymbolInformation} according to the GSI versions
	 * prior to 7.00 specification.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon unexpected fields.
	 * @throws CancelledException Upon user cancellation.
	 */
	private void deserializeGsiPre70HashTable(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {

		int numBucketsBytes = 4 * (numHashRecords + 1);
		if (reader.numRemaining() < numBucketsBytes) {
			throw new PdbException("Not enough data for GSI");
		}
		int numRecordsBytes = (reader.numRemaining() - numBucketsBytes);

		PdbByteReader hashRecordsReader = reader.getSubPdbByteReader(numRecordsBytes);
		PdbByteReader bucketsReader = reader.getSubPdbByteReader(numBucketsBytes);
		if (reader.hasMore()) {
			throw new PdbException("Unexpected extra information at and of GSI stream");
		}

		hashBucketOffsets = new ArrayList<>();
		while (bucketsReader.hasMore()) {
			monitor.checkCanceled();
			hashBucketOffsets.add(bucketsReader.parseInt());
		}

		// Note: each offset value is into an array of structures that are 12 bytes in length, but
		// whose on-disk size is 8 bytes.  These are the structures in the hashRecordsReader.  So
		// take the offset and multiple by 2/3 to get the byte offset into the reader for the
		// actual record.  Still need to deal with the collision logic after that.

		deserializeHashRecords(hashRecordsReader, monitor);
	}

	/**
	 * Deserialize the body of the {@link GlobalSymbolInformation} according to the GSI 7.00
	 * specification.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon unexpected fields.
	 * @throws CancelledException Upon user cancellation.
	 */
	private void deserializeGsi70HashTable(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {

		if (reader.numRemaining() != hashRecordsLength + bucketsLength) {
			throw new PdbException("Data count mismatch in GSI stream");
		}
		if (hashRecordsLength == 0 || bucketsLength == 0) {
			return;
		}

		PdbByteReader hashRecordsReader = reader.getSubPdbByteReader(hashRecordsLength);
		PdbByteReader bucketsReader = reader.getSubPdbByteReader(bucketsLength);

		deserializedCompressedHashBuckets(bucketsReader, monitor);

//		int i = 0;
//		for (int x : hashBucketOffsets) {
//			System.out.println(String.format("0x%04x: 0x%08x", i++, x));
//		}
		// Note: each offset value is into an array of structures that are 12 bytes in length, but
		// whose on-disk size is 8 bytes.  These are the structures in the hashRecordsReader.  So
		// take the offset and multiple by 2/3 to get the byte offset into the reader for the
		// actual record.  Still need to deal with the collision logic after that.

		deserializeHashRecords(hashRecordsReader, monitor);
	}

	/**
	 * Deserializes a compressed set of hash buckets from the {@link PdbByteReader} provided.  The
	 * data comes as a bit-mapped representation of which indices should contain the data followed
	 * by a flat set of hash buckets that will be set at those indices in the order provided.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws CancelledException Upon user cancellation.
	 */
	private void deserializedCompressedHashBuckets(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {

		PdbByteReader bitEncoderReader = reader.getSubPdbByteReader(hashRecordsBitMapLength);
		// Throw away extra bytes between bit map and buckets.
		reader.getSubPdbByteReader(numExtraBytes);
		while (bitEncoderReader.hasMore() && reader.hasMore()) {
			monitor.checkCanceled();
			long val = bitEncoderReader.parseUnsignedIntVal();
			//bitEncoded[index++] = val;
			for (int bit = 0; bit < 32 && reader.hasMore(); bit++) {
				monitor.checkCanceled();
				if ((val & 0x01L) == 0x01L) {
					hashBucketOffsets.add(reader.parseInt());
				}
				else {
					hashBucketOffsets.add(-1);
				}
				val >>= 1;
			}
		}
		// Both readers should run out of data at the same time.  We can have more bit encoder
		// data as long as there are not more bits set in the values.  The following logic
		// checks this integrity.
		if (reader.hasMore()) {
			throw new PdbException("Compressed GSI Hash Buckets corrupt");
		}
		while (bitEncoderReader.hasMore()) {
			monitor.checkCanceled();
			if (bitEncoderReader.parseUnsignedIntVal() != 0) {
				throw new PdbException("Compressed GSI Hash Buckets corrupt");
			}
		}

	}

	/**
	 * 
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	private void deserializeHashRecords(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		hashRecords = new TreeSet<>();
		while (reader.hasMore()) {
			monitor.checkCanceled();
			SymbolHashRecord record = new SymbolHashRecord();
			record.parse(reader);
			hashRecords.add(record);
		}
	}

	/**
	 * Generates a list of symbols from the information that we have.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	private void generateSymbolsList(TaskMonitor monitor) throws PdbException, CancelledException {
		symbols = new ArrayList<>();
		Map<Long, AbstractMsSymbol> map = pdb.getDatabaseInterface().getSymbolMap();
		for (SymbolHashRecord record : hashRecords) {
			monitor.checkCanceled();
			long offset = record.getOffset();
			AbstractMsSymbol symbol = map.get(offset);
			if (symbol == null) {
				throw new PdbException("PDB corrupted");
			}
			symbols.add(symbol);
		}
	}

	/**
	 * Debug method for dumping information from this {@link GlobalSymbolInformation}.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	void dump(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("GlobalSymbolInformation-------------------------------------\n");
		dumpHeader(builder);
		dumpHashRecords(builder);
		builder.append("\nEnd GlobalSymbolInformation---------------------------------\n");
		writer.write(builder.toString());
	}

}
