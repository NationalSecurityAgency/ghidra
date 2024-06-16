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

	public static final int HASH_PRE70_HEADER_LENGTH = 0;
	public static final int HASH_70_HEADER_LENGTH = 16;
	public static final int HASH_HEADER_MIN_READ_LENGTH =
		Integer.max(HASH_PRE70_HEADER_LENGTH, HASH_70_HEADER_LENGTH);

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected AbstractPdb pdb;
	protected int streamNumber;

	protected int symbolHashLength;
	protected int symbolHashOffset;

	protected int hashHeaderLength;
	protected int headerSignature;
	protected int versionNumber;
	protected int hashRecordsLength;
	protected int bucketsLength;
	protected int hashRecordsOffset;
	protected int bucketsOffset;

	protected int numHashRecords;
	protected int numExtraBytes;
	protected int hashRecordsBitMapLength;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor
	 * @param pdbIn {@link AbstractPdb} that owns the Abstract Symbol Information to process
	 * @param streamNumber the stream number containing the symbol information
	 */
	public AbstractSymbolInformation(AbstractPdb pdbIn, int streamNumber) {
		pdb = pdbIn;
		this.streamNumber = streamNumber;
	}

	/**
	 * Returns the Offsets of symbols within the symbol table; these are gotten from the
	 *  HashRecords and modified to point to the size field of the symbols in the symbol table
	 * @return offsets
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	public List<Long> getModifiedHashRecordSymbolOffsets() throws CancelledException, PdbException {
		return generateModifiedSymbolOffsets();
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Parses and returns the hash bucket offsets
	 * @return the offsets
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	List<Integer> getHashBucketOffsets() throws CancelledException, PdbException {
		try {
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(streamNumber, bucketsOffset, bucketsLength);
			if (headerSignature == HEADER_SIGNATURE) {
				return deserializedCompressedHashBuckets(reader);
			}
			return deserializedHashBuckets(reader);
		}
		catch (IOException e) {
			Msg.error(this, String.format(
				"PDB: Error creating hash buckets while reading stream %d offset %d and length %d",
				streamNumber, bucketsOffset, bucketsLength));
			return new ArrayList<>();
		}
	}

	/**
	 * Parses and returns the hash records
	 * @return the hash records
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	Set<SymbolHashRecord> getHashRecords() throws CancelledException, PdbException {
		try {
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(streamNumber, hashRecordsOffset, hashRecordsLength);
			return deserializeHashRecords(reader);
		}
		catch (IOException e) {
			Msg.error(this, String.format(
				"PDB: Error creating hash records while reading stream %d offset %d and length %d",
				streamNumber, hashRecordsOffset, hashRecordsLength));
			return new TreeSet<>();
		}
	}

	/**
	 * Deserialize basic {@link AbstractSymbolInformation} from the appropriate stream in the Pdb
	 * so that later queries can be made
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	abstract void initialize() throws IOException, PdbException, CancelledException;

	/**
	 * Initializes values such as offset, lengths, and numbers
	 */
	void initializeValues() {
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
	 * Debug method for dumping information from this {@link AbstractSymbolInformation}
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException issue reading PDB or upon issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	void dump(Writer writer) throws IOException, CancelledException, PdbException {
		StringBuilder builder = new StringBuilder();
		builder.append("AbstractSymbolInformation-----------------------------------\n");
		dumpHashHeader(builder);
		dumpHashBasics(builder);
		dumpHashRecords(builder);
		builder.append("\nEnd AbstractSymbolInformation-------------------------------\n");
		writer.write(builder.toString());
	}

	/**
	 * Debug method for dumping basic information from this {@link AbstractSymbolInformation}
	 * @param builder {@link StringBuilder} to which to dump the information
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
	 * Debug method for dumping information from this {@link AbstractSymbolInformation} header
	 * @param builder {@link StringBuilder} to which to dump the information
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
	 * Generates a list of symbols from the information that we have
	 * @return the offsets
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	protected List<Long> generateModifiedSymbolOffsets() throws PdbException, CancelledException {
		List<Long> modifiedHashRecordSymbolOffsets = new ArrayList<>();
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return modifiedHashRecordSymbolOffsets;
		}
		Set<SymbolHashRecord> hashRecords = getHashRecords();
		for (SymbolHashRecord record : hashRecords) {
			pdb.checkCancelled();
			long offset = record.getOffset() - 2; // Modified offset
			modifiedHashRecordSymbolOffsets.add(offset);
		}
		return modifiedHashRecordSymbolOffsets;
	}

	/**
	 * Debug method for dumping hash records from this {@link AbstractSymbolInformation}
	 * @param builder {@link StringBuilder} to which to dump the information
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	protected void dumpHashRecords(StringBuilder builder)
			throws CancelledException, PdbException {
		Set<SymbolHashRecord> hashRecords = getHashRecords();
		builder.append("HashRecords-------------------------------------------------\n");
		builder.append("numHashRecords: " + hashRecords.size() + "\n");
		for (SymbolHashRecord record : hashRecords) {
			pdb.checkCancelled();
			builder.append(
				String.format("0X%08X  0X%04X\n", record.getOffset(), record.getReferenceCount()));
		}
		builder.append("\nEnd HashRecords---------------------------------------------\n");
	}

	protected void deserializeHashHeader() throws PdbException, CancelledException, IOException {
		MsfStream stream = pdb.getMsf().getStream(streamNumber);
		PdbByteReader reader =
			pdb.getReaderForStreamNumber(streamNumber, symbolHashOffset,
				HASH_HEADER_MIN_READ_LENGTH);
		deserializeHashHeader(reader, stream.getLength());
	}

	/**
	 * Deserialize the header of the Hash from the {@link PdbByteReader} provided
	 * @param reader {@link PdbByteReader} containing the data buffer to process
	 * @throws PdbException upon not enough data left to parse
	 */
	private void deserializeHashHeader(PdbByteReader reader, int streamLength) throws PdbException {
		headerSignature = reader.parseInt();
		if (headerSignature == HEADER_SIGNATURE) {
			hashHeaderLength = HASH_70_HEADER_LENGTH;
			versionNumber = reader.parseInt();
			hashRecordsLength = reader.parseInt();
			bucketsLength = reader.parseInt();
			hashRecordsOffset = symbolHashOffset + reader.getIndex();
			bucketsOffset = hashRecordsOffset + hashRecordsLength;
		}
		else {
			hashHeaderLength = HASH_PRE70_HEADER_LENGTH;
			reader.reset(); // There was no header
			// Calculate the values
			bucketsLength = 4 * (numHashRecords + 1);
			if (streamLength < bucketsLength) {
				throw new PdbException("Not enough data for symbol hash buckets.");
			}
			hashRecordsLength = streamLength - bucketsLength;
			hashRecordsOffset = symbolHashOffset + 0;
			bucketsOffset = hashRecordsOffset + hashRecordsLength;
		}
	}

	/**
	 * Deserializes a compressed set of hash buckets from the {@link PdbByteReader} provided.  The
	 * data comes as a bit-mapped representation of which indices should contain the data followed
	 * by a flat set of hash buckets that will be set at those indices in the order provided
	 * @param reader {@link PdbByteReader} containing the data buffer to process
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	private List<Integer> deserializedCompressedHashBuckets(PdbByteReader reader)
			throws PdbException, CancelledException {

		List<Integer> hashBucketOffsets = new ArrayList<>();

		PdbByteReader bitEncoderReader = reader.getSubPdbByteReader(hashRecordsBitMapLength);
		// Throw away extra bytes between bit map and buckets.
		reader.getSubPdbByteReader(numExtraBytes);
		while (bitEncoderReader.hasMore() && reader.hasMore()) {
			pdb.checkCancelled();
			long val = bitEncoderReader.parseUnsignedIntVal();
			//bitEncoded[index++] = val;
			for (int bit = 0; bit < 32 && reader.hasMore(); bit++) {
				pdb.checkCancelled();
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
			pdb.checkCancelled();
			if (bitEncoderReader.parseUnsignedIntVal() != 0) {
				throw new PdbException("Compressed GSI Hash Buckets corrupt");
			}
		}
		return hashBucketOffsets;

	}

	/**
	 * Deserializes a normal/non-compressed set of hash buckets from the {@link PdbByteReader}
	 * provided.
	 * @param reader {@link PdbByteReader} containing the data buffer to process
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	private List<Integer> deserializedHashBuckets(PdbByteReader reader)
			throws PdbException, CancelledException {
		List<Integer> hashBucketOffsets = new ArrayList<>();
		while (reader.hasMore()) {
			pdb.checkCancelled();
			hashBucketOffsets.add(reader.parseInt());
		}
		return hashBucketOffsets;
	}

	// The following note is from previous incantation of this code (before changing to on-demand
	//  reading of components).  It still might be applicable here or elsewhere.
	//
	// Note: each offset value is into an array of structures that are 12 bytes in length, but
	// whose on-disk size is 8 bytes.  These are the structures in the hashRecordsReader.  So
	// take the offset and multiple by 2/3 to get the byte offset into the reader for the
	// actual record.  Still need to deal with the collision logic after that.
	/**
	 * Deserializes and returns the hash records
	 * @param reader {@link PdbByteReader} containing the data buffer to process
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	private Set<SymbolHashRecord> deserializeHashRecords(PdbByteReader reader)
			throws PdbException, CancelledException {
		Set<SymbolHashRecord> hashRecords = new TreeSet<>();
		while (reader.hasMore()) {
			pdb.checkCancelled();
			SymbolHashRecord record = new SymbolHashRecord();
			record.parse(reader);
			hashRecords.add(record);
		}
		return hashRecords;
	}

	// NOTE Iterator below is not good at this point in time, as we had been working with
	//  a TreeSet, which is ordered.  The iterator below is acting on hash bins which are
	//  as random as the hash key makes them.  TODO: consider other options.  For now going back
	//  to creating the whole TreeSet.

//	public ModifiedOffsetIterator iterator() {
//		return new ModifiedOffsetIterator();
//	}
//
//	//==============================================================================================
//	/**
//	 * Iterator for {@link SymbolGroup} that iterates through {@link AbstractMsSymbol
//	 * AbstractMsSymbols}
//	 */
//	public class ModifiedOffsetIterator implements Iterator<Long> {
//
//		private int streamOffset;
//		private int streamOffsetLimit;
//		private float factor;
//
//		private Long value;
//
//		public ModifiedOffsetIterator() {
//			initGet();
//		}
//
//		@Override
//		public boolean hasNext() {
//			return (value != null);
//		}
//
//		/**
//		 * Peeks at and returns the next symbol without incrementing to the next.  If none are
//		 * left, then throws NoSuchElementException and reinitializes the state for a new
//		 * iteration.
//		 * @see #initGet()
//		 * @return the next symbol
//		 * @throws NoSuchElementException if there are no more elements
//		 */
//		public Long peek() throws NoSuchElementException {
//			if (value == null) {
//				throw new NoSuchElementException();
//			}
//			return value;
//		}
//
//		@Override
//		public Long next() {
//			if (value == null) {
//				throw new NoSuchElementException();
//			}
//			Long offer = value;
//			value = retrieveNext();
//			return offer;
//		}
//
//		private Long retrieveNext() {
//			if (streamNumber == MsfStream.NIL_STREAM_NUMBER) {
//				return null;
//			}
//			if (streamOffset >= streamOffsetLimit) {
//				return null;
//			}
//			try {
//				PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, streamOffset,
//					SymbolHashRecord.RECORD_SIZE);
//				SymbolHashRecord record = new SymbolHashRecord();
//				record.parse(reader);
//				streamOffset += SymbolHashRecord.RECORD_SIZE;
//				// Minus 2 for the "modified" offset points to the length field in the "other"
//				//  stream
//				return record.getOffset() - 2;
//			}
//			catch (CancelledException | PdbException | IOException e) {
//				return null;
//			}
//		}
//
//		/**
//		 * Initialized the mechanism for requesting the symbols in sequence.
//		 * @see #hasNext()
//		 */
//		void initGet() {
//			if (streamNumber == MsfStream.NIL_STREAM_NUMBER) {
//				streamOffset = 0;
//				streamOffsetLimit = 0;
//				return;
//			}
//			streamOffset = hashRecordsOffset;
//			streamOffsetLimit = hashRecordsLength;
//			value = retrieveNext();
//			long num = streamOffsetLimit - hashRecordsOffset;
//			float factor = num <= 0 ? 0.0F : 1.0F / (num);
//		}
//
//		/**
//		 * Returns value from 0 to 100 as a rough percentage of having iterated through all records
//		 * @return the percentage
//		 */
//		public long getPercentageDone() {
//			long num = streamOffset - hashRecordsOffset;
//			return (long) (factor * num);
//		}
//	}
}
