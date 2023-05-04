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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.msf.Msf;
import ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfStream;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents the the Windows PDB file.  This class is only suitable for reading; not
 *  for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public abstract class AbstractPdb implements AutoCloseable {

	private static final int PDB_DIRECTORY_STREAM_NUMBER = 1;

	// Items below begin in Pdb200
	private static final int VERSION_NUMBER_SIZE = 4;

	// Items below begin in Pdb400
	// "MINI" = 0x4d 0x49 0x4e 0x49 = 0x494e494d  featMinimalDbgInfo
	private static final int MINIMAL_DEBUG_INFO_PARAM = 0x494e494d;
	// "NOTM" = 0x4e 0x4f 0x54 0x4d = 0x4d544f4e  featNoTypeMerge
	private static final int NO_TYPE_MERGE_PARAM = 0x4d544f4e;

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected Msf msf;

	protected PdbReaderOptions readerOptions;

	// Items below begin in Pdb200
	protected int versionNumber = 0;
	protected int signature = 0;
	//Number of times PDB updated.
	protected int pdbAge = 0;
	protected int dbiAge = 0;

	protected TypeProgramInterface typeProgramInterface;
	protected PdbDebugInfo debugInfo;

	protected Processor targetProcessor = Processor.UNKNOWN;

	// Items below begin in Pdb400
	protected boolean minimalDebugInfo = false;
	protected boolean noTypeMerge = false;
	protected boolean hasIdStream = false;

	protected List<String> strings;
	protected List<Integer> parameters;
	protected NameTable nameTable;

	protected TypeProgramInterface itemProgramInterface;  //IPI seems to be a TPI.

	// Items below begin in Pdb700
	protected GUID guid; // We can return null by not initializing the guid.
	//protected GUID guid =
	//  new GUID(0, (short) 0, (short) 0, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });

	protected boolean substreamsDeserialized = false;

	//==============================================================================================
	// Ghidra-specific:
	private PdbReaderMetrics pdbReaderMetrics = new PdbReaderMetrics(this);

	/**
	 * Returns the {@link PdbReaderMetrics} used by this class.
	 * @return the PdbMetrics.
	 */
	public PdbReaderMetrics getPdbReaderMetrics() {
		return pdbReaderMetrics;
	}

	//==============================================================================================
	// Utility methods
	//==============================================================================================

	/**
	 * Parses an address segment typically used by some {@link AbstractMsSymbol} type.  In addition,
	 *  {@link PdbReaderMetrics} may be updated for segment information
	 * @param reader the reader from which to parse the segment
	 * @return the segment
	 * @throws PdbException upon not enough data left to parse
	 */
	public int parseSegment(PdbByteReader reader) throws PdbException {
		int segment = reader.parseUnsignedShortVal();
		pdbReaderMetrics.witnessedSectionSegmentNumber(segment);
		return segment;
	}

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Closes the {@link AbstractPdb} and resources that it uses
	 * @throws IOException for file I/O reasons
	 */
	@Override
	public void close() throws IOException {
		if (msf != null) {
			msf.close();
		}
	}

	/**
	 * Returns the {@link PdbReaderOptions} for this PDB
	 * @return the {@link PdbReaderOptions} for this PDB
	 */
	public PdbReaderOptions getPdbReaderOptions() {
		return readerOptions;
	}

	/**
	 * Returns the main {@link PdbIdentifiers} found in the PDB Directory
	 * @return {@link PdbIdentifiers} of information
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon error in processing components
	 */
	public PdbIdentifiers getIdentifiers() throws IOException, PdbException {
		parseDBI();
		if (debugInfo != null) {
			try {
				// dbiAge and targetProcessor set during deserialization of new DBI header
				debugInfo.deserialize(true);
			}
			catch (CancelledException e) {
				throw new AssertException(e); // unexpected
			}
		}
		int age = pdbAge;
		if (dbiAge > 0) {
			age = dbiAge;
		}
		return new PdbIdentifiers(versionNumber, signature, age, guid, targetProcessor);
	}

	/**
	 * Deserializes this PDB from the underlying {@link Msf}
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon error in processing components
	 * @throws CancelledException upon user cancellation
	 */
	public void deserialize()
			throws IOException, PdbException, CancelledException {
		// msf should only be null for testing versions of PDB.
		if (msf == null) {
			return;
		}
		deserializeDirectory();

		//directoryStream.dump(Integer.MAX_VALUE);
		//System.out.println(pdb.dumpDirectory());

		//pdb.dumpStream(2, Integer.MAX_VALUE);
//		pdb.dumpStream(2, 0x400);
		//		pdb.dumpStream(3, 0x400);
//		pdb.dumpStream(4, 0x400);

		deserializeSubstreams();
//		pdb.dumpSubStreams();

		// pdb.dumpGlobalSymbols(); //TODO: evaluate where/who calls.
		//  Currently in dumpSubStreams() and parsed in deserializeSubStreams()

		PdbLog.message(pdbReaderMetrics::getPostProcessingReport);
	}

	/**
	 * Returns the Version Number of the PDB
	 * @return Version Number of the PDB
	 */
	public int getVersionNumber() {
		return versionNumber;
	}

	/**
	 * Returns the Signature of the PDB
	 * @return Signature of the PDB
	 */
	public int getSignature() {
		return signature;
	}

	/**
	 * Returns the Age of the PDB
	 * @return Age of the PDB
	 */
	public int getAge() {
		return pdbAge;
	}

	/**
	 * Returns the GUID for the PDB
	 * @return {@link GUID} for the PDB
	 */
	public GUID getGuid() {
		return guid;
	}

	/**
	 * Tells whether the PDB file has been completely deserialized yet
	 * @return {@code true} if has been deserialized
	 */
	public boolean isDeserialized() {
		return substreamsDeserialized;
	}

	/**
	 * Get the index number of the target processor used for compilation
	 * @return Index number of the target processor used for compilation
	 * @see Processor
	 * @see RegisterName
	 */
	public Processor getTargetProcessor() {
		return targetProcessor;
	}

	/**
	 * Returns whether there is minimal debug information
	 * @return {@code true} if there is minimal debug information
	 */
	public boolean hasMinimalDebugInfo() {
		return minimalDebugInfo;
	}

	/**
	 * Set the index number of the target processor used for compilation.
	 * @param targetProcessorIn Processor identifier.
	 * @see Processor
	 * @see RegisterName
	 */
	// TODO: this method should be package protected
	public void setTargetProcessor(Processor targetProcessorIn) {
		/**
		 * Should we allow an overwrite?  The {@link PdbNewDebugInfo} value (mapped from
		 * {@link ImageFileMachine}) should be processed and laid down first.  Subsequent values
		 * can come from {@link AbstractCompile2MsSymbol} and {@link Compile3MsSymbol}.  Note:
		 * {@link PdbDebugInfo} does not carry {@link ImageFileMachine}, and thus no mapping
		 * is applied.
		 */
		if (targetProcessor == Processor.UNKNOWN) {
			targetProcessor = targetProcessorIn;
		}
	}

	/**
	 * Set the age as specified by the new DBI header.  A value of 0 corresponds
	 * to the old DBI header
	 * @param dbiAge age as specified by the new DBI header
	 */
	void setDbiAge(int dbiAge) {
		this.dbiAge = dbiAge;
	}

	/**
	 * Returns the {@link TypeProgramInterface} component
	 * @return {@link TypeProgramInterface} component or null if not available
	 */
	public TypeProgramInterface getTypeProgramInterface() {
		return typeProgramInterface;
	}

	/**
	 * Returns the ItemProgramInterface (of type {@link TypeProgramInterface})
	 *  component
	 * @return ItemProgramInterface (of type {@link TypeProgramInterface}) component
	 * or null if not available
	 */
	public TypeProgramInterface getItemProgramInterface() {
		return itemProgramInterface;
	}

	/**
	 * Returns the {@link PdbDebugInfo} component
	 * @return {@link PdbDebugInfo} component or null if not available
	 */
	public PdbDebugInfo getDebugInfo() {
		return debugInfo;
	}

	/**
	 * Returns the record for the associated record number, which is expected to match the
	 *  desired class
	 * @param recordNumber the record number
	 * @return the record
	 */
	public AbstractMsType getTypeRecord(RecordNumber recordNumber) {
		return getTypeRecord(recordNumber, AbstractMsType.class);
	}

	/**
	 * Returns the record for the associated record number, which is expected to match the
	 *  desired class
	 * @param <T> class return type
	 * @param recordNumber record number
	 * @param typeClass desired class type for return
	 * @return the record
	 */
	public <T extends AbstractMsType> T getTypeRecord(RecordNumber recordNumber,
			Class<T> typeClass) {
		recordNumber = fixupTypeIndex(recordNumber, typeClass);
		AbstractMsType msType =
			getTPI(recordNumber.getCategory()).getRecord(recordNumber.getNumber());
		if (!typeClass.isInstance(msType)) {
			if (!recordNumber.isNoType()) {
				PdbLog.logGetTypeClassMismatch(msType, typeClass);
			}
			return null;
		}
		return typeClass.cast(msType);
	}

	RecordNumber fixupTypeIndex(RecordNumber recordNumber, Class<?> typeClass) {
		if (recordNumber.getNumber() < 0) {
			int newNumber = recordNumber.getNumber() & Integer.MAX_VALUE;
			switch (recordNumber.getCategory()) {
				case TYPE:
					// Switch to item
					return RecordNumber.itemRecordNumber(newNumber);
				case ITEM:
					// Switch to type (we have no evidence or documentation for this to happen).
					return RecordNumber.typeRecordNumber(newNumber);
				default:
					break;
			}
		}
		return recordNumber;
	}

	private TPI getTPI(RecordCategory category) {
		switch (category) {
			case TYPE:
				return typeProgramInterface;
			case ITEM:
				return itemProgramInterface;
			default:
				return null;
		}
	}

	/**
	 * Returns a name from the {@link NameTable} pertaining to the index argument
	 * @param index index of the name
	 * @return name
	 */
	public String getNameFromNameIndex(int index) {
		return nameTable.getNameFromStreamNumber(index);
	}

	/**
	 * Returns an index of the {@link String} name argument in the {@link NameTable}
	 * @param name name for which to find the index
	 * @return index of the name argument
	 */
	public int getNameIndexFromName(String name) {
		return nameTable.getStreamNumberFromName(name);
	}

	/**
	 * Returns a name from the {@link NameTable} pertaining to the byte-offset in the block of
	 *  names for the table
	 * @param offset byte offset of the name in the {@link NameTable} block
	 * @return name at the byte offset in the Name Table
	 */
	public String getNameStringFromOffset(int offset) {
		return nameTable.getNameStringFromOffset(offset);
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Returns the number of bytes needed to store a PDB version number
	 * @return number of bytes needed to store a PDV version number
	 */
	static int getVersionNumberSize() {
		return VERSION_NUMBER_SIZE;
	}

	/**
	 * Deserializes PDB Version Number from the PDB Directory Stream in the {@link Msf}
	 * @param msf {@link Msf} underlying the PDB of which to probe
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @return version number
	 * @throws IOException on file I/O issues
	 * @throws PdbException on parsing issues
	 * @throws CancelledException upon user cancellation
	 */
	static int deserializeVersionNumber(Msf msf, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {

		MsfStream directoryStream = msf.getStream(PDB_DIRECTORY_STREAM_NUMBER);
		if (directoryStream.getLength() < AbstractPdb.getVersionNumberSize()) {
			throw new PdbException("Directory Stream too short");
		}
		byte[] bytes = directoryStream.read(0, AbstractPdb.getVersionNumberSize());
		PdbByteReader pdbDirectoryReader = new PdbByteReader(bytes);
		return pdbDirectoryReader.parseInt();
	}

	/**
	 * Constructor
	 * @param msf {@link Msf} foundation for the PDB
	 * @param readerOptions {@link PdbReaderOptions} used for processing the PDB
	 * @throws IOException upon file IO seek/read issues
	 * @throws PdbException upon unknown value for configuration or error in processing components
	 */
	AbstractPdb(Msf msf, PdbReaderOptions readerOptions) throws IOException, PdbException {
		this.msf = msf;
		this.readerOptions = readerOptions;
		strings = new ArrayList<>();
		parameters = new ArrayList<>();
		nameTable = new NameTable(this);
	}

	/**
	 * Deserializes the main {@link PdbIdentifiers} found in the PDB Directory from the
	 *  {@link PdbByteReader}
	 * @param monitor {@link TaskMonitor} used for checking cancellation
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon error parsing a field
	 * @throws CancelledException upon user cancellation
	 */
	abstract void deserializeIdentifiersOnly(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException;

	/**
	 * Returns the filename
	 * @return the filename
	 */
	public String getFilename() {
		return msf.getFilename();
	}

	/**
	 * Returns the TaskMonitor
	 * @return the monitor
	 */
	public TaskMonitor getMonitor() {
		return msf.getMonitor();
	}

	/**
	 * Check to see if this monitor has been canceled
	 * @throws CancelledException if monitor has been cancelled
	 */
	public void checkCancelled() throws CancelledException {
		getMonitor().checkCancelled();
	}

	/**
	 * Returns the {@link Msf} foundation for the PDB
	 * @return {@link Msf} foundation of the PDB
	 */
	Msf getMsf() {
		return msf;
	}

	//TODO  Not sure if we will keep this method or if more gets added to it.
	/**
	 * Deserializes the sub-streams for this {@link AbstractPdb} object
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon error in processing components
	 * @throws CancelledException upon user cancellation
	 */
	void deserializeSubstreams()
			throws IOException, PdbException, CancelledException {

		if (substreamsDeserialized) {
			return;
		}

		TypeProgramInterfaceParser tpiParser = new TypeProgramInterfaceParser();

		typeProgramInterface = tpiParser.parse(this);
		if (typeProgramInterface != null) {
			typeProgramInterface.deserialize();
		}

		boolean ipiStreamHasNoName = ItemProgramInterfaceParser.hackCheckNoNameForStream(nameTable);
		pdbReaderMetrics.witnessIpiDetection(ipiStreamHasNoName, hasIdStream);
		if (hasIdStream || ipiStreamHasNoName) {
			ItemProgramInterfaceParser ipiParser = new ItemProgramInterfaceParser();
			itemProgramInterface = ipiParser.parse(this);
			if (itemProgramInterface != null) {
				itemProgramInterface.deserialize();
			}
			//processDependencyIndexPairList();
			//dumpDependencyGraph();
		}

		parseDBI();
		if (debugInfo != null) {
			debugInfo.deserialize(false);
		}

		substreamsDeserialized = true;
	}

	private PdbDebugInfo parseDBI() throws IOException, PdbException {
		if (debugInfo == null) {
			PdbDebugInfoParser dbiParser = new PdbDebugInfoParser();
			debugInfo = dbiParser.parse(this);
		}
		return debugInfo;
	}

	/**
	 * Returns a {@link PdbByteReader} initialized with the complete contents of the
	 * {@link MsfStream} referenced by {@code streamNumber}
	 * @param streamNumber the stream number of the {@link MsfStream} from which to load the data
	 * @return the {@link PdbByteReader}
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws CancelledException upon user cancellation
	 */
	PdbByteReader getReaderForStreamNumber(int streamNumber)
			throws IOException, CancelledException {
		return getReaderForStreamNumber(streamNumber, 0, MsfStream.MAX_STREAM_LENGTH);
	}

	/**
	 * Returns a {@link PdbByteReader} initialized with up to  {@code numToRead} byte of content
	 *  (less if not available) from the {@link MsfStream} referenced by {@code streamNumber}
	 *  starting at {@code streamOffset}
	 * @param streamNumber the stream number of the {@link MsfStream} from which to load the data
	 * @param streamOffset starting location within the {@link MsfStream} from which to get the
	 *  data
	 * @param numToRead number of bytes used to initialize the {@link PdbByteReader}
	 * @return the {@link PdbByteReader}
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws CancelledException upon user cancellation
	 */
	PdbByteReader getReaderForStreamNumber(int streamNumber, int streamOffset, int numToRead)
			throws IOException, CancelledException {
		MsfStream stream = msf.getStream(streamNumber);
		numToRead = Math.min(numToRead, stream.getLength() - streamOffset);
		byte[] bytes = stream.read(streamOffset, numToRead);
		PdbByteReader reader = new PdbByteReader(bytes);
		return reader;
	}

	/**
	 * Debug method to dump the number of bytes for the specified stream to a {@link String}
	 * @param streamNumber the stream number to dump
	 * @param maxOut the maximum number of bytes to dump
	 * @return {@link String} of pretty output
	 */
	String dumpStream(int streamNumber, int maxOut) {
		StringBuilder builder = new StringBuilder();
		builder.append(msf.getStream(streamNumber).dump(maxOut));
		return builder.toString();
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Deserializes PDB Directory from the {@link PdbByteReader}
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon error parsing a field
	 * @throws CancelledException upon user cancellation
	 */
	abstract void deserializeDirectory()
			throws IOException, PdbException, CancelledException;

	/**
	 * Dumps the PDB Directory to {@link Writer}.  This package-protected method is for
	 *  debugging only.
	 * @param writer {@link Writer}.
	 * @throws IOException on issue writing to the {@link Writer}.
	 */
	public abstract void dumpDirectory(Writer writer) throws IOException;

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================

	/**
	 * Reads the Directory stream and returns a {@link PdbByteReader} of its contents
	 * @return {@link PdbByteReader} requested
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws CancelledException upon user cancellation
	 */
	protected PdbByteReader getDirectoryReader()
			throws IOException, CancelledException {
		return getReaderForStreamNumber(PDB_DIRECTORY_STREAM_NUMBER, 0,
			MsfStream.MAX_STREAM_LENGTH);
	}

	/**
	 * Deserializes the Version, Signature, and Age
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @throws PdbException upon not enough data left to parse
	 */
	protected void deserializeVersionSignatureAge(PdbByteReader reader) throws PdbException {
		versionNumber = reader.parseInt();
		signature = reader.parseInt();
		pdbAge = reader.parseInt();
	}

	/**
	 * Dumps the Version Signature and Age.  This package-protected method is for debugging only
	 * @return {@link String} of pretty output
	 */
	protected String dumpVersionSignatureAge() {
		StringBuilder builder = new StringBuilder();
		builder.append("DirectoryHeader---------------------------------------------");
		builder.append("\nversionNumber: ");
		builder.append(versionNumber);
		builder.append("\nsignature: ");
		builder.append(Integer.toHexString(signature));
		builder.append("\nage: ");
		builder.append(pdbAge);
		return builder.toString();
	}

	/**
	 * Deserializes the Parameters
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon error parsing a string
	 * @throws CancelledException upon user cancellation
	 */
	protected void deserializeParameters(PdbByteReader reader)
			throws IOException, PdbException, CancelledException {
		nameTable.deserializeDirectory(reader);
		// Read the parameters.
		while (reader.hasMore()) {
			getMonitor().checkCancelled();
			int val = reader.parseInt();
			parameters.add(val);
		}
		// Check the parameters for IDs
		for (int param : parameters) {
			getMonitor().checkCancelled();
			if (param == MINIMAL_DEBUG_INFO_PARAM) {
				minimalDebugInfo = true;
			}
			else if (param == NO_TYPE_MERGE_PARAM) {
				noTypeMerge = true;
			}
			// Putting all of these >= ID after the specific == tests above
			//  so that no >= tests in the ID section trigger off of any
			//  of the above flags
			else if (param >= PdbParser.VC110_ID) {
				hasIdStream = true;
			}
		}
	}

	/**
	 * Dumps the Parameters to a {@link String}.  This package-protected method is for
	 *  debugging only
	 * @return {@link String} of pretty output
	 */
	protected String dumpParameters() {
		StringBuilder builder = new StringBuilder();
		builder.append(nameTable.dump());
		builder.append("\nParameters--------------------------------------------------\n");
		for (int i = 0; i < parameters.size(); i++) {
			builder.append(String.format("parameter[%d]: 0x%08x %d\n", i, parameters.get(i),
				parameters.get(i)));
		}
		builder.append("Booleans----------------------------------------------------");
		builder.append("\nminimalDebugInfo: ");
		builder.append(minimalDebugInfo);
		builder.append("\nnoTypeMerge: ");
		builder.append(noTypeMerge);
		builder.append("\nhasIdStream: ");
		builder.append(hasIdStream);
		builder.append("\n");
		return builder.toString();
	}

	/**
	 * Dumps the Sub-Streams to a {@link Writer}.  This package-protected method is for
	 *  debugging only
	 * @param writer {@link Writer}
	 * @throws IOException on issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	public void dumpSubStreams(Writer writer) throws IOException, CancelledException, PdbException {
		writer.write("SubStreams--------------------------------------------------\n");
		if (typeProgramInterface != null) {
			writer.write("TypeProgramInterface----------------------------------------\n");
			typeProgramInterface.dump(writer);
			writer.write("End TypeProgramInterface------------------------------------\n");
			writer.write("\n");
		}
		if (itemProgramInterface != null) {
			writer.write("ItemProgramInterface----------------------------------------\n");
			itemProgramInterface.dump(writer);
			writer.write("End ItemProgramInterface------------------------------------\n");
		}
		if (debugInfo != null) {
			writer.write("DebugInfo---------------------------------------------------\n");
			debugInfo.dump(writer);
			writer.write("End DebugInfo-----------------------------------------------\n");
		}
	}

}
