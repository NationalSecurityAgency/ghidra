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

import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Type Program Interface component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public abstract class AbstractTypeProgramInterface implements TPI {

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
	protected RecordCategory recordCategory;
	private int streamNumber;

	protected int headerLength;
	protected int typeIndexMin;
	protected int typeIndexMaxExclusive;
	protected int dataLength;
	protected TypeProgramInterfaceHash hash;

	protected Map<Integer, PrimitiveMsType> primitiveTypesByRecordNumber = new HashMap<>();
	protected List<AbstractMsType> typeList = new ArrayList<>();

	protected int versionNumber = 0;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns this {@link AbstractTypeProgramInterface}.
	 * @param recordCategory the RecordCategory of these records.
	 * @param streamNumber The stream number that contains the
	 *  {@link AbstractTypeProgramInterface} data.
	 */
	public AbstractTypeProgramInterface(AbstractPdb pdb, RecordCategory recordCategory,
			int streamNumber) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
		this.recordCategory = recordCategory;
		this.streamNumber = streamNumber;
		hash = new TypeProgramInterfaceHash();
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
	 * Returns the TypeIndexMin.
	 * @return The TypeIndexMin value from the header.
	 */
	@Override
	public int getTypeIndexMin() {
		return typeIndexMin;
	}

	/**
	 * Returns the TypeIndexMaxExclusive.
	 * @return TypeIndexMaxExclusive value from the header.
	 */
	@Override
	public int getTypeIndexMaxExclusive() {
		return typeIndexMaxExclusive;
	}

	/**
	 * Retrieves the {@link AbstractMsType} record indicated by the recordNumber.  The record must
	 *  already have been parsed and inserted into the list.
	 * @param recordNumber Record number to look up.
	 * @return {@link AbstractMsType} pertaining to the record number.
	 */
	@Override
	public AbstractMsType getRecord(int recordNumber) {
		if (recordNumber < 0 || recordNumber - typeIndexMin > typeList.size()) {
			// This should not happen, but we have seen it and cannot yet explain it.
			// So, for now, we are creating and returning a new BadMsType.
			PdbLog.logBadTypeRecordIndex(this, recordNumber);
			BadMsType type = new BadMsType(pdb, 0);
			type.setRecordNumber(RecordNumber.make(recordCategory, recordNumber));
			return type;
		}
		if (recordNumber < typeIndexMin) {
			PrimitiveMsType primitive = primitiveTypesByRecordNumber.get(recordNumber);
			if (primitive == null) {
				primitive = new PrimitiveMsType(pdb, recordNumber);
				primitiveTypesByRecordNumber.put(recordNumber, primitive);
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
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, monitor);

		deserializeHeader(reader);

		// Commented out, but this is currently where we might put this method.  See the note
		//  placed within the method (deserializeHashStreams()) for more information about why
		//  we have this commented out.
		//hash.deserializeHashStreams(monitor);

		deserializeTypeRecords(reader, monitor);

		return versionNumber;
	}

	/**
	 * Dumps this class.  This package-protected method is for debugging only.
	 * @param writer {@link Writer} to which to write the debug dump.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	void dump(Writer writer) throws IOException {
		writer.write("TypeProgramInterfaceHeader----------------------------------\n");
		dumpHeader(writer);
		writer.write("\nEnd TypeProgramInterfaceHeader------------------------------\n");
		writer.write("TypeProgramInterfaceRecords---------------------------------\n");
		dumpTypeRecords(writer);
		writer.write("\nEnd TypeProgramInterfaceRecords-----------------------------\n");
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
		Objects.requireNonNull(pdb, "pdb cannot be null");
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
	 * @param writer {@link Writer} to which to dump the header.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	protected abstract void dumpHeader(Writer writer) throws IOException;

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Deserializes the Type Records of this class.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected void deserializeTypeRecords(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		int recordLength;
		int recordNumber = typeIndexMin;
		TypeParser parser = pdb.getTypeParser();

		while (reader.hasMore()) {
			monitor.checkCanceled();

			recordLength = reader.parseUnsignedShortVal();
			PdbByteReader recordReader = reader.getSubPdbByteReader(recordLength);
			recordReader.markAlign(2);

			// No need to call either of these, because we do not expect the record number
			//  to have a high bit set here.  If we did, we would have to check 'category' to
			//  know which of the two to call, and we'd have to create an AbstractTypeIndex:
			//    	parseTypeRecordNumber(recordReader, recordNumber);
			//    	parseItemRecordNumber(recordReader, recordNumber);
			AbstractMsType type =
				parser.parseRecord(recordReader, RecordNumber.make(recordCategory, recordNumber));
			typeList.add(type);
			recordNumber++;
		}
		if (recordNumber != typeIndexMaxExclusive) {
			PdbLog.message(this.getClass().getSimpleName() + ": Header max records: " +
				typeIndexMaxExclusive + "; parsed records: " + recordNumber);
		}
	}

	//TODO: more to do for outputting individual records (might want a toString or dump method
	// on each).
	/**
	 * Dumps the Type Records.  This method is for debugging only.
	 * @param writer {@link Writer} to which to dump the records.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	protected void dumpTypeRecords(Writer writer) throws IOException {
		int recordNum = typeIndexMin;
		for (AbstractMsType type : typeList) {
			StringBuilder builder = new StringBuilder();
			builder.append("------------------------------------------------------------\n");
			builder.append("Record: ");
			builder.append(recordNum);
			builder.append("\n");
			if (type != null) {
				builder.append(type.getClass().getSimpleName());
				builder.append("\n");
				builder.append(type.toString());
				builder.append("\n");
			}
			else {
				builder.append("(null)\n"); //Temporary output value.
			}
			writer.write(builder.toString());
			recordNum++;
		}
	}

	//==============================================================================================
	// Private Classes
	//==============================================================================================
	// TODO: implementation not complete; questioning current usefulness of this class, but
	//  leaving the partial implementation of future work if we desire to pursue it further.
	protected class TypeProgramInterfaceHash {
		int hashStreamNumber;
		int hashStreamNumberAuxiliary;
		int hashKeySize;
		int numHashBins;
		int offsetHashVals;
		int lengthHashVals;
		int offsetTypeIndexOffsetPairs;
		int lengthTypeIndexOffsetPairs;
		int offsetHashAdjustment;
		int lengthHashAdjustment;

		private List<TiOff> tiOffs = new ArrayList<>();

		/**
		 * Deserializes the {@link TypeProgramInterfaceHash}.
		 * @param reader {@link PdbByteReader} from which to deserialize the data.
		 * @throws PdbException Upon not enough data left to parse.
		 */
		protected void deserializeHeader800(PdbByteReader reader) throws PdbException {
			hashStreamNumber = reader.parseUnsignedShortVal();
			hashStreamNumberAuxiliary = reader.parseUnsignedShortVal();
			hashKeySize = reader.parseInt();
			numHashBins = reader.parseInt();
			offsetHashVals = reader.parseInt();
			lengthHashVals = reader.parseInt();
			offsetTypeIndexOffsetPairs = reader.parseInt();
			lengthTypeIndexOffsetPairs = reader.parseInt();
			offsetHashAdjustment = reader.parseInt();
			lengthHashAdjustment = reader.parseInt();
		}

		/**
		 * Deserializes the {@link TypeProgramInterfaceHash}.
		 * @param hashStreamNumberParam Stream number of the hash.
		 * @param typeIndexMinParam The IndexMin to set/use.
		 * @param typeIndexMaxExclusiveParam One greater than the MaxIndex to set/use.
		 * @throws PdbException Upon not enough data left to parse.
		 */
		protected void initHeader200500(int hashStreamNumberParam, int typeIndexMinParam,
				int typeIndexMaxExclusiveParam) throws PdbException {
			hashStreamNumber = hashStreamNumberParam;
			hashStreamNumberAuxiliary = 0xffff;
			hashKeySize = 2;
			numHashBins = 0x1000;
			offsetHashVals = 0;
			lengthHashVals = (typeIndexMaxExclusiveParam - typeIndexMinParam) * hashKeySize;
			offsetTypeIndexOffsetPairs = lengthHashVals;
			lengthTypeIndexOffsetPairs = -1;
			offsetHashAdjustment = 0;
			lengthHashAdjustment = -1;
		}

		// TODO: parsing not complete
		// Suppress "unused" for hashBuffer, typeInfoOffsetPairsBuffer, hashAdjustmentBuffer
		/**
		 * *UNDER CONSTRUCTION* Deserializes the Hash Streams...
		 * @param monitor {@link TaskMonitor} used for checking cancellation.
		 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
		 *  inability to read required bytes.
		 * @throws PdbException Upon error in processing components.
		 * @throws CancelledException Upon user cancellation.
		 */
		@SuppressWarnings("unused") // for method unused.
		protected void deserializeHashStreams(TaskMonitor monitor)
				throws IOException, PdbException, CancelledException {
			// I don't believe we need to parse and process the hash table.  They seemingly are
			//  used to point from a TypeIndex to a raw (byte[]) Type Record.  We are not
			//  currently maintaining our records in this raw form; we are processing (parsing) 
			//  them as we read each record buffer.
			// Note that we have no evidence of how the Auxiliary stream is used.  Its
			//  contents might need to get concatenated with the contents of the primary
			//  stream before the processing takes place, but the API does not show it being
			//  used at all.
			if (hashStreamNumber == 0xffff) {
				return;
			}
			PdbByteReader reader = pdb.getReaderForStreamNumber(hashStreamNumber, monitor);
			//System.out.println(reader.dump());

			reader.setIndex(offsetHashVals);
			PdbByteReader hashValsReader = reader.getSubPdbByteReader(lengthHashVals);
			reader.setIndex(offsetTypeIndexOffsetPairs);
			PdbByteReader typeInfoOffsetPairsReader =
				reader.getSubPdbByteReader(lengthTypeIndexOffsetPairs);
			reader.setIndex(offsetHashAdjustment);
			PdbByteReader hashAdjustmentReader = reader.getSubPdbByteReader(lengthHashAdjustment);

			// I think we might need to do these in this reverse order.  TODO: not sure it matters
			deserializeHashAdjustment(hashAdjustmentReader, monitor);
			deserializeTypeIndexOffsetPairs(typeInfoOffsetPairsReader, monitor);
			deserializeHashVals(hashValsReader, monitor);

			if (hashStreamNumberAuxiliary == 0xffff) {
				return;
			}
			PdbByteReader readerAuxiliary =
				pdb.getReaderForStreamNumber(hashStreamNumberAuxiliary, monitor);
			//readerAuxiliary.dump();
		}

		//see tpi.cpp line 527
		// TODO: incomplete implementation.
		// Seems to be hash values only... one per type record.
		private void deserializeHashVals(PdbByteReader reader, TaskMonitor monitor)
				throws PdbException, CancelledException {
			if (hashKeySize == 2) {
				for (int index = typeIndexMin; index < typeIndexMaxExclusive; index++) {
					monitor.checkCanceled();
					long hashVal = reader.parseUnsignedShortVal();
					if (hashVal < 0 || hashVal >= numHashBins) {
						throw new PdbException("Bad hashVal: " + hashVal);
					}
				}
			}
			else if (hashKeySize == 4) {
				for (int index = typeIndexMin; index < typeIndexMaxExclusive; index++) {
					monitor.checkCanceled();
					long hashVal = reader.parseUnsignedIntVal();
					if (hashVal < 0 || hashVal >= numHashBins) {
						throw new PdbException("Bad hashVal: " + hashVal);
					}
				}
			}
			else {
				throw new PdbException("Bad hashKeySize: " + hashKeySize);
			}
		}

		// TODO: incomplete implementation.
		// Seems to be hash values only... one per type record.
		// TODO: only doing 32-bit versions in this method...  see next method (unimplemented)
		//  which could/should use TiOff16 class.  Was calling it init...() because was thinking
		//  we were going to build it up differently, but really need to look at tpi.h/cpp
		//  for what to do.
		private void deserializeTypeIndexOffsetPairs(PdbByteReader reader, TaskMonitor monitor)
				throws PdbException, CancelledException {
			int numPairs = lengthTypeIndexOffsetPairs / TiOff32.size;
			if (numPairs * TiOff32.size != lengthTypeIndexOffsetPairs) {
				throw new PdbException("Corruption in Length of Type Index Pairs;");
			}
			long previousTypeIndex = -1;
			for (int i = 0; i < numPairs; i++) {
				monitor.checkCanceled();
				TiOff tiOff = new TiOff32(reader);
				if (tiOff.getTypeIndex() <= previousTypeIndex) {
					throw new PdbException("Corruption in TypeIndex/Offset pairs: out of order");
				}
				previousTypeIndex = tiOff.getTypeIndex();
				tiOffs.add(tiOff);
			}
		}

		@SuppressWarnings("unused") // for method unused
		private void initTypeIndexToRec200400(PdbByteReader reader, TaskMonitor monitor) {
			// TODO: incomplete implementation.  Was going to parse specific 2.0 and 4.0 ver stuff.
		}

		@SuppressWarnings("unused") // for baseIndex not yet used.  Will be used for start of
		// linear search.
		protected long getOffsetForTypeIndex(int typeIndex) {
			int retVal = Collections.binarySearch(tiOffs, new KeyTiOff(typeIndex));
			if (retVal < 0) {
				retVal = -retVal - 1;
			}
			long baseIndex = tiOffs.get(retVal).getOffset();
			// TODO: need to do a linear search within the stream for the actual record.
			// Do not forget to consider the header offset within the stream.  For example, the
			// TPI header might be 56 bytes, so an offset of 1000 should really be 1056 into the
			// stream.  Or it could be 1000 into a separate PdbByteReader that only has records.
			return 0; // TODO: Need to return the actual offset after the linear search.
		}

		private void deserializeHashAdjustment(PdbByteReader reader, TaskMonitor monitor) {
			// TODO: incomplete implementation.
		}

		/**
		 * Dumps the this {@link TypeProgramInterfaceHash}.  This method is for debugging only.
		 * @return {@link String} of pretty output.
		 */
		protected String dump() {
			StringBuilder builder = new StringBuilder();
			builder.append("Hash--------------------------------------------------------");
			builder.append("\nhashStreamNumber: ");
			builder.append(hashStreamNumber);
			builder.append("\nhashStreamNumberAuxiliary: ");
			builder.append(hashStreamNumberAuxiliary);
			builder.append("\nhashKeySize: ");
			builder.append(hashKeySize);
			builder.append("\nnumHashBins: ");
			builder.append(numHashBins);
			builder.append("\noffsetHashVals: ");
			builder.append(offsetHashVals);
			builder.append("\nlengthHashVals: ");
			builder.append(lengthHashVals);
			builder.append("\noffsetTypeIndexOffsetPairs: ");
			builder.append(offsetTypeIndexOffsetPairs);
			builder.append("\nlengthTypeIndexOffsetPairs: ");
			builder.append(lengthTypeIndexOffsetPairs);
			builder.append("\noffsetHashAdjustment: ");
			builder.append(offsetHashAdjustment);
			builder.append("\nlengthHashAdjustment: ");
			builder.append(lengthHashAdjustment);
			return builder.toString();
		}
	}

	private abstract class TiOff implements Comparable<TiOff> {
		// Note that these should be unsigned 32-bit values from MSFT perspective, but we
		// are falsely limiting them to signed (thus 31 bits).
		protected int typeIndex;
		protected int offset;

		protected TiOff(PdbByteReader reader) throws PdbException {
			parse(reader);
		}

		/**
		 * This method is only intended to be used to create a dummy key for performing
		 *  a binary search.  That is the reason that an {@code offset} parameter is not
		 *  specified.  The offset is set to zero.
		 * @param typeIndex The type index to fill into the key.
		 */
		protected TiOff(int typeIndex) {
			this.typeIndex = typeIndex;
			offset = 0;
		}

		protected int getTypeIndex() {
			return typeIndex;
		}

		protected int getOffset() {
			return offset;
		}

		@Override
		public int compareTo(TiOff o) {
			return typeIndex - o.typeIndex;
		}

		protected abstract void parse(PdbByteReader reader) throws PdbException;

		protected abstract int getSize();
	}

	private class KeyTiOff extends TiOff {
		/**
		 * This method is only intended to be used to create a dummy key for performing
		 *  a binary search.  That is the reason that an {@code offset} parameter is not
		 *  specified.  The offset is set to zero.
		 * @param typeIndex The type index to fill into the key.
		 */
		protected KeyTiOff(int typeIndex) {
			super(typeIndex);
		}

		@Override
		protected int getSize() {
			throw new AssertException("Invalid to use this method.");
		}

		@Override
		protected void parse(PdbByteReader reader) {
			throw new AssertException("Invalid to use this method.");
		}
	}

	private class TiOff32 extends TiOff {
		protected static final int size = 8;

		protected TiOff32(PdbByteReader reader) throws PdbException {
			super(reader);
		}

		@Override
		protected int getSize() {
			return size;
		}

		@Override
		protected void parse(PdbByteReader reader) throws PdbException {
			// Note that these should be unsigned 32-bit values from MSFT perspective, but we
			// are falsely limiting them to signed (thus 31 bits).
			typeIndex = reader.parseInt();
			offset = reader.parseInt();
		}
	}

	@SuppressWarnings("unused") // for class currently not used, but would be counterpart to
	// TiOff32.
	private class TiOff16 extends TiOff {
		protected static final int size = 4;

		protected TiOff16(PdbByteReader reader) throws PdbException {
			super(reader);
		}

		@Override
		protected int getSize() {
			return size;
		}

		@Override
		protected void parse(PdbByteReader reader) throws PdbException {
			typeIndex = reader.parseUnsignedShortVal();
			offset = reader.parseUnsignedShortVal();
		}
	}
}
