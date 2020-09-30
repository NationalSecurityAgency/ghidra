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

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Global Symbol Information or Public Symbol Information component of a
 * PDB file.  This class is only suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 *   @see GlobalSymbolInformation
 *   @see PublicSymbolInformation
 */
public abstract class AbstractSymbolInformation {

	public static final int HEADER_SIGNATURE = 0xffffffff;

	public static final int GSI70 = 0xeffe0000 + 19990810; // 0xf12f091a = -248575718

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected AbstractPdb pdb;
	protected int numHashRecords;
	protected int numExtraBytes;
	protected int hashRecordsBitMapLength;

	protected int headerSignature;
	protected int versionNumber;
	protected int hashRecordsLength;
	protected int bucketsLength;

	// These are read from "buckets."
	protected List<Integer> hashBucketOffsets = new ArrayList<>();
	protected Set<SymbolHashRecord> hashRecords = new TreeSet<>();
	protected List<Long> modifiedHashRecordSymbolOffsets = new ArrayList<>();

	protected List<AbstractMsSymbol> symbols = new ArrayList<>();

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdbIn {@link AbstractPdb} that owns the Abstract Symbol Information to process.
	 */
	public AbstractSymbolInformation(AbstractPdb pdbIn) {
		pdb = pdbIn;
	}

	/**
	 * Returns the list of symbols for this {@link AbstractSymbolInformation}.
	 * @return the symbols.
	 */
	public List<AbstractMsSymbol> getSymbols() {
		return symbols;
	}

	/**
	 * Returns the Offsets of symbols within the symbol table; these are gotten from the
	 *  HashRecords and modified to point to the size field of the symbols in the symbol table.
	 * @return offsets
	 */
	public List<Long> getModifiedHashRecordSymbolOffsets() {
		return modifiedHashRecordSymbolOffsets;
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Deserialize the {@link AbstractSymbolInformation} from the appropriate stream in the Pdb.
	 * @param streamNumber the stream number containing the information to deserialize.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	void deserialize(int streamNumber, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		if (pdb.hasMinimalDebugInfo()) {
			hashRecordsBitMapLength = 0x8000;
			numExtraBytes = 0; // I believe;
			numHashRecords = 0x3ffff;
		}
		else {
			hashRecordsBitMapLength = 0x200;
			numExtraBytes = 4;
			numHashRecords = 0x1000;
		}
	}

	/**
	 * Debug method for dumping information from this {@link AbstractSymbolInformation}.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	void dump(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("AbstractSymbolInformation-----------------------------------\n");
		dumpHashHeader(builder);
		dumpHashBasics(builder);
		dumpHashRecords(builder);
		builder.append("\nEnd AbstractSymbolInformation-------------------------------\n");
		writer.write(builder.toString());
	}

	/**
	 * Debug method for dumping basic information from this {@link AbstractSymbolInformation}.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	protected void dumpHashBasics(StringBuilder builder) {
		builder.append("HashBasics--------------------------------------------------\n");
		builder.append("hashRecordsBitMapLength: ");
		builder.append(hashRecordsBitMapLength);
		builder.append("\nnumExtraBytes: ");
		builder.append(numExtraBytes);
		builder.append("\nnumHashRecords: ");
		builder.append(numHashRecords);
		builder.append("\nEnd HashBasics----------------------------------------------\n");
	}

	/**
	 * Debug method for dumping information from this {@link AbstractSymbolInformation} header.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	protected void dumpHashHeader(StringBuilder builder) {
		builder.append("HashHeader--------------------------------------------------\n");
		builder.append("headerSignature: ");
		builder.append(headerSignature);
		builder.append("\nversionNumber: ");
		builder.append(versionNumber);
		builder.append("\nlengthHashRecords: ");
		builder.append(hashRecordsLength);
		builder.append("\nlengthBuckets: ");
		builder.append(bucketsLength);
		builder.append("\nEnd HashHeader----------------------------------------------\n");
	}

	/**
	 * Generates a list of symbols from the information that we have.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon PDB corruption.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected void generateSymbolsList(TaskMonitor monitor)
			throws PdbException, CancelledException {
		symbols = new ArrayList<>();
		Map<Long, AbstractMsSymbol> symbolsByOffset = pdb.getDebugInfo().getSymbolsByOffset();
		for (SymbolHashRecord record : hashRecords) {
			monitor.checkCanceled();
			long offset = record.getOffset() - 2; // Modified offset
			AbstractMsSymbol symbol = symbolsByOffset.get(offset);
			modifiedHashRecordSymbolOffsets.add(offset);
			if (symbol == null) {
				throw new PdbException("PDB corrupted");
			}
			symbols.add(symbol);
		}
	}

	/**
	 * Debug method for dumping hash records from this {@link AbstractSymbolInformation}.
	 * @param builder {@link StringBuilder} to which to dump the information.
	 */
	protected void dumpHashRecords(StringBuilder builder) {
		builder.append("HashRecords-------------------------------------------------\n");
		builder.append("numHashRecords: " + hashRecords.size() + "\n");
		for (SymbolHashRecord record : hashRecords) {
			builder.append(
				String.format("0X%08X  0X%04X\n", record.getOffset(), record.getReferenceCount()));
		}
		builder.append("\nEnd HashRecords---------------------------------------------\n");
	}

	/**
	 * Deserializes the hash table for the symbols.
	 * @param reader {@link PdbByteReader} containing the data buffer to process.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected void deserializeHashTable(PdbByteReader reader, TaskMonitor monitor)
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

	/**
	 * Deserialize the body of the {@link AbstractSymbolInformation} according to the GSI versions
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
	 * Deserialize the body of the {@link AbstractSymbolInformation} according to the GSI 7.00
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
	 * @throws PdbException Upon not enough data left to parse.
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

}
