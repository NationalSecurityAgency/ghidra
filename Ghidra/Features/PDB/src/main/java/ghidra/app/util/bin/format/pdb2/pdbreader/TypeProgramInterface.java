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
public abstract class TypeProgramInterface implements TPI {

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

	private record OffLen(int offset, int length) {} // record type for quick random access

	private List<OffLen> offLenRecords;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor
	 * @param pdb {@link AbstractPdb} that owns this {@link TypeProgramInterface}
	 * @param recordCategory the RecordCategory of these records
	 * @param streamNumber the stream number that contains the {@link TypeProgramInterface} data
	 */
	public TypeProgramInterface(AbstractPdb pdb, RecordCategory recordCategory, int streamNumber) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
		this.recordCategory = recordCategory;
		this.streamNumber = streamNumber;
		hash = new TypeProgramInterfaceHash();
	}

	/**
	 * Returns the number of bytes needed to store a {@link TypeProgramInterface}
	 *  version number
	 * @return the number of bytes read from the bytes array
	 */
	static int getVersionNumberSize() {
		return VERSION_NUMBER_SIZE;
	}

	/**
	 * Deserializes Version Number of the {@link TypeProgramInterface} from the
	 *  {@link PdbByteReader}
	 * @param reader {@link PdbByteReader} from which to deserialize
	 * @return version number
	 * @throws PdbException upon not enough data left to parse
	 */
	static int deserializeVersionNumber(PdbByteReader reader) throws PdbException {
		return reader.parseInt();
	}

	/**
	 * Returns the TypeIndexMin
	 * @return the TypeIndexMin value from the header
	 */
	@Override
	public int getTypeIndexMin() {
		return typeIndexMin;
	}

	/**
	 * Returns the TypeIndexMaxExclusive
	 * @return TypeIndexMaxExclusive value from the header
	 */
	@Override
	public int getTypeIndexMaxExclusive() {
		return typeIndexMaxExclusive;
	}

	/**
	 * Retrieves the {@link AbstractMsType} record indicated by the recordNumber
	 * @param recordNumber record number to look up
	 * @return {@link AbstractMsType} pertaining to the record number
	 */
	@Override
	public AbstractMsType getRandomAccessRecord(int recordNumber) {
		if (recordNumber < 0 || recordNumber - typeIndexMin > offLenRecords.size()) {
			// This should not happen, but we have seen it and cannot yet explain it.
			// So, for now, we are creating and returning a new BadMsType.
			PdbLog.logBadTypeRecordIndex(this, recordNumber);
			BadMsType badType = new BadMsType(pdb, 0);
			badType.setRecordNumber(RecordNumber.make(recordCategory, recordNumber));
			return badType;
		}
		PrimitiveMsType primitive = getPrimitiveRecord(recordNumber);
		if (primitive != null) {
			return primitive;
		}

		RecordNumber rn = RecordNumber.make(recordCategory, recordNumber);
		OffLen offLen = offLenRecords.get(recordNumber - typeIndexMin);

		try {
			PdbByteReader recordReader =
				pdb.getReaderForStreamNumber(streamNumber, offLen.offset(), offLen.length());
			recordReader.markAlign(2);
			return TypeParser.parseRecord(pdb, recordReader, rn);
		}
		catch (PdbException | IOException | CancelledException e) {
			BadMsType badType = new BadMsType(pdb, 0);
			badType.setRecordNumber(RecordNumber.make(recordCategory, recordNumber));
			return badType;
		}
	}

	protected PrimitiveMsType getPrimitiveRecord(int recordNumber) {
		if (recordNumber >= typeIndexMin) {
			return null;
		}
		PrimitiveMsType primitive = primitiveTypesByRecordNumber.get(recordNumber);
		if (primitive == null) {
			primitive = new PrimitiveMsType(pdb, recordNumber);
			primitiveTypesByRecordNumber.put(recordNumber, primitive);
		}
		return primitive;
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Deserializes and initializes {@link TypeProgramInterface} basic information so that later
	 * queries can be made
	 * @return version number of the {@link TypeProgramInterface}
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	int initialize() throws IOException, PdbException, CancelledException {
		if (pdb.getMsf() == null) {
			// Should only be null dummy PDBs used for testing.
			throw new PdbException("Unexpected null MSF.");
		}
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber);

		deserializeHeader(reader);

		// Commented out, but this is currently where we might put this method.  See the note
		//  placed within the method (deserializeHashStreams()) for more information about why
		//  we have this commented out.
		//hash.deserializeHashStreams(pdb.getMonitor());

		// TODO: consider other mechanisms than offset/length values for use by an iterator.
		//  Need to be able to access by record number, so might not have much choice.
		createOffLenRecords(reader);

		return versionNumber;
	}

	/**
	 * Dumps this class.  This package-protected method is for debugging only
	 * @param writer {@link Writer} to which to write the debug dump
	 * @throws IOException on issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 */
	void dump(Writer writer) throws IOException, CancelledException {
		writer.write("TypeProgramInterfaceHeader----------------------------------\n");
		dumpHeader(writer);
		writer.write("\nEnd TypeProgramInterfaceHeader------------------------------\n");
		writer.write("TypeProgramInterfaceRecords---------------------------------\n");
		dumpTypeRecords(writer);
		writer.write("\nEnd TypeProgramInterfaceRecords-----------------------------\n");
	}

	/**
	 * IMPORTANT: This method is for testing only.  It allows us to set a basic object.
	 * <p>
	 * Note: not all values are initialized.  This is a dummy constructor used to create a dummy
	 * {@link TypeProgramInterface}.
	 * <p>
	 * Note: not all values of this class get initialized by this method.
	 * @param pdb {@link AbstractPdb} that owns this class
	 * @param typeIndexMin the IndexMin to set/use
	 * @param typeIndexMaxExclusive one greater than the MaxIndex to set/use
	 */
	TypeProgramInterface(AbstractPdb pdb, int typeIndexMin, int typeIndexMaxExclusive) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
		this.typeIndexMin = typeIndexMin;
		this.typeIndexMaxExclusive = typeIndexMaxExclusive;
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Deserializes the Header of this class
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @throws PdbException upon not enough data left to parse
	 */
	protected abstract void deserializeHeader(PdbByteReader reader) throws PdbException;

	/**
	 * Dumps the Header.  This method is for debugging only
	 * @param writer {@link Writer} to which to dump the header
	 * @throws IOException on issue writing to the {@link Writer}
	 */
	protected abstract void dumpHeader(Writer writer) throws IOException;

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	private void createOffLenRecords(PdbByteReader reader) throws PdbException, CancelledException {
		int savedIndex = reader.getIndex();
		offLenRecords = new ArrayList<>();
		while (reader.hasMore()) {
			pdb.checkCancelled();
			int recordLength = reader.parseUnsignedShortVal();
			// reading offset after parsing length so we have correct offset to read from later
			int offset = reader.getIndex();
			reader.skip(recordLength);
			offLenRecords.add(new OffLen(offset, recordLength));
		}
		reader.setIndex(savedIndex); // restore reader to original state
	}

	//TODO: more to do for outputting individual records (might want a toString or dump method
	// on each).
	/**
	 * Dumps the Type Records.  This method is for debugging only
	 * @param writer {@link Writer} to which to dump the records
	 * @throws IOException on issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 */
	protected void dumpTypeRecords(Writer writer) throws IOException, CancelledException {
		for (int recordNum = typeIndexMin; recordNum < typeIndexMaxExclusive; recordNum++) {
			pdb.checkCancelled();
			AbstractMsType type = getRandomAccessRecord(recordNum);
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
		 * Deserializes the {@link TypeProgramInterfaceHash}
		 * @param reader {@link PdbByteReader} from which to deserialize the data
		 * @throws PdbException upon not enough data left to parse
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
		 * Deserializes the {@link TypeProgramInterfaceHash}
		 * @param hashStreamNumberParam stream number of the hash
		 * @param typeIndexMinParam the IndexMin to set/use
		 * @param typeIndexMaxExclusiveParam one greater than the MaxIndex to set/use
		 * @throws PdbException upon not enough data left to parse
		 */
		protected void initHeader200500(int hashStreamNumberParam, int typeIndexMinParam,
				int typeIndexMaxExclusiveParam) throws PdbException {
			hashStreamNumber = hashStreamNumberParam;
			hashStreamNumberAuxiliary = MsfStream.NIL_STREAM_NUMBER;
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
		 * @param monitor {@link TaskMonitor} used for checking cancellation
		 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
		 *  inability to read required bytes
		 * @throws PdbException upon error in processing components
		 * @throws CancelledException upon user cancellation
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
			if (hashStreamNumber == MsfStream.NIL_STREAM_NUMBER) {
				return;
			}
			PdbByteReader reader = pdb.getReaderForStreamNumber(hashStreamNumber);
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

			if (hashStreamNumberAuxiliary == MsfStream.NIL_STREAM_NUMBER) {
				return;
			}
			PdbByteReader readerAuxiliary = pdb.getReaderForStreamNumber(hashStreamNumberAuxiliary);
			//readerAuxiliary.dump();
		}

		//see tpi.cpp line 527
		// TODO: incomplete implementation.
		// Seems to be hash values only... one per type record.
		private void deserializeHashVals(PdbByteReader reader, TaskMonitor monitor)
				throws PdbException, CancelledException {
			if (hashKeySize == 2) {
				for (int index = typeIndexMin; index < typeIndexMaxExclusive; index++) {
					monitor.checkCancelled();
					long hashVal = reader.parseUnsignedShortVal();
					if (hashVal < 0 || hashVal >= numHashBins) {
						throw new PdbException("Bad hashVal: " + hashVal);
					}
				}
			}
			else if (hashKeySize == 4) {
				for (int index = typeIndexMin; index < typeIndexMaxExclusive; index++) {
					monitor.checkCancelled();
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
				monitor.checkCancelled();
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
		 * Dumps the this {@link TypeProgramInterfaceHash}.  This method is for debugging only
		 * @param writer the writer
		 * @throws IOException upon issue with writing to the writer
		 */
		void dump(Writer writer) throws IOException {
			PdbReaderUtils.dumpHead(writer, this);
			writer.write("\nhashStreamNumber: " + hashStreamNumber);
			writer.write("\nhashStreamNumberAuxiliary: " + hashStreamNumberAuxiliary);
			writer.write("\nhashKeySize: " + hashKeySize);
			writer.write("\nnumHashBins: " + numHashBins);
			writer.write("\noffsetHashVals: " + offsetHashVals);
			writer.write("\nlengthHashVals: " + lengthHashVals);
			writer.write("\noffsetTypeIndexOffsetPairs: " + offsetTypeIndexOffsetPairs);
			writer.write("\nlengthTypeIndexOffsetPairs: " + lengthTypeIndexOffsetPairs);
			writer.write("\noffsetHashAdjustment: " + offsetHashAdjustment);
			writer.write("\nlengthHashAdjustment: " + lengthHashAdjustment);
			writer.write("\n");
			PdbReaderUtils.dumpTail(writer, this);
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
		 * a binary search.  That is the reason that an {@code offset} parameter is not
		 * specified.  The offset is set to zero
		 * @param typeIndex the type index to fill into the key
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
		 * a binary search.  That is the reason that an {@code offset} parameter is not
		 * specified.  The offset is set to zero
		 * @param typeIndex the type index to fill into the key
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
