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
 * This class represents DebugInfo (DBI) component of a PDB file.
 * This class is only suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public abstract class PdbDebugInfo {

	protected static final int VERSION_NUMBER_SIZE = 4;

	public static final int STREAM_NUMBER_SIZE = 2;
	public static final int LENGTH_SIZE = 4;

	/**
	 * These are Section Contribution Versions (SCV) 6.00 and 14.00.  We are building to the MSFT
	 *  API.  They have chosen to mix in some magic along the way for these--perhaps to ensure that
	 *  the the value will be a large unsigned 32-bit or a negative 32-bit.  We store the value
	 *  in a java long, so that we can maintain the signed-ness of the values, if necessary.  MSFT
	 *  is probably trying to prevent these values from being mimicked by data in the versions
	 *  prior to v 6.00.
	 */
	private static final long SCV600 = 0xeffe0000L + 19970605L;
	private static final long SCV1400 = 0xeffe0000L + 20140516L;

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected AbstractPdb pdb;
	protected int streamNumber;

	protected long versionNumber = 0; // unsigned 32-bit

	protected int streamNumberGlobalStaticSymbolsHashMaybe = 0; // unsigned 16-bit
	protected int streamNumberPublicStaticSymbolsHashMaybe = 0; // unsigned 16-bit
	protected int streamNumberSymbolRecords = 0; // unsigned 16-bit

	protected int lengthModuleInformationSubstream = 0; // signed 32-bit
	protected int lengthSectionContributionSubstream = 0; // signed 32-bit
	protected int lengthSectionMap = 0; // signed 32-bit
	protected int lengthFileInformation = 0; // signed 32-bit

	protected List<AbstractModuleInformation> moduleInformationList = new ArrayList<>();
	protected List<AbstractSectionContribution> sectionContributionList = new ArrayList<>();
	protected List<SegmentMapDescription> segmentMapList = new ArrayList<>();

	protected SymbolRecords symbolRecords;
	protected GlobalSymbolInformation globalSymbolInformation;
	protected PublicSymbolInformation publicSymbolInformation;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns this Database Interface.
	 * @param streamNumber The stream number of the stream containing the Database Interface.
	 */
	public PdbDebugInfo(AbstractPdb pdb, int streamNumber) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
		this.streamNumber = streamNumber;
		globalSymbolInformation = new GlobalSymbolInformation(pdb);
		publicSymbolInformation = new PublicSymbolInformation(pdb);
		symbolRecords = new SymbolRecords(pdb);
	}

	/**
	 * Returns the number of bytes needed to store the version number.
	 * @return The number of bytes needed to store the version number.
	 */
	public static int getVersionNumberSize() {
		return VERSION_NUMBER_SIZE;
	}

	/**
	 * Deserializes the {@link PdbDebugInfo}-based instance.
	 * The pdb is updated with dbiAge and targetProcessor during deserialization 
	 * of new DBI header.
	 * @param headerOnly if true only the DBI header fields will be parsed
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @return The version number of the Database Interface.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	public long deserialize(boolean headerOnly, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		if (headerOnly) {
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(streamNumber, 0, getHeaderLength(), monitor);
			deserializeHeader(reader);
		}
		else {
			PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
			deserializeHeader(reader);
			deserializeInternalSubstreams(reader, monitor);
			deserializeAdditionalSubstreams(monitor);
		}
		return versionNumber;
	}

	/**
	 * Returns the number of modules.
	 * @return the number of modules
	 */
	public int getNumModules() {
		return moduleInformationList.size();
	}

	/**
	 * Returns the list of {@link AbstractModuleInformation}, indexed by the module number.
	 * @return List of {@link AbstractModuleInformation}.
	 */
	public List<AbstractModuleInformation> getModuleInformationList() {
		return moduleInformationList;
	}

	/**
	 * Returns the {@link AbstractModuleInformation}, based on the moduleNumber.
	 * @param moduleNumber The module number being requested (1 to {@link #getNumModules()}).
	 * @return {@link AbstractModuleInformation} for the moduleNumber provided.
	 * @throws PdbException Upon moduleNumber out of range or no module information.
	 */
	public AbstractModuleInformation getModuleInformation(int moduleNumber) throws PdbException {
		if (moduleNumber < 1 || moduleNumber > moduleInformationList.size()) {
			throw new PdbException("ModuleNumber out of range: " + moduleNumber);
		}
		AbstractModuleInformation moduleInfo = moduleInformationList.get(moduleNumber - 1);
		if (moduleInfo == null) {
			throw new PdbException("Null AbstractModuleInformation");
		}
		return moduleInfo;
	}

	/**
	 * Returns the list of combined global/public symbols.
	 * @return {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols.
	 */
	public Map<Long, AbstractMsSymbol> getSymbolsByOffset() {
		return symbolRecords.getSymbolsByOffset();
	}

	/**
	 * Returns the buffer-offset-to-symbol map for the module as specified by moduleNumber.
	 * @param moduleNumber The number ID of the module for which to return the list.
	 * @return {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols for the specified module.
	 * @throws PdbException Upon moduleNumber out of range or no module information.
	 */
	public Map<Long, AbstractMsSymbol> getModuleSymbolsByOffset(int moduleNumber)
			throws PdbException {
		if (moduleNumber < 0 || moduleNumber > moduleInformationList.size()) {
			throw new PdbException("ModuleNumber out of range: " + moduleNumber);
		}
		if (moduleNumber == 0) {
			return getSymbolsByOffset();
		}
		return symbolRecords.getModuleSymbolsByOffset(moduleNumber - 1);
	}

	/**
	 * Returns the {@link AbstractMsSymbol} from the main symbols for the 
	 *  actual symbol record offset (which is past the length and symbol type fields).
	 * @param offset the offset of the symbol (beyond length and symbol type fields); this is the
	 *  offset value specified by many symbol type records.
	 * @return the symbol group for the module or null if not found.
	 */
	public AbstractMsSymbol getSymbolForOffsetOfRecord(long offset) {
		return getSymbolsByOffset().get(offset - 4);
	}

	/**
	 * Returns the {@link AbstractMsSymbol} for the module as specified by moduleNumber and
	 *  actual symbol record offset (which is past the length and symbol type fields).
	 * @param moduleNumber The number ID of the module (1 to {@link #getNumModules()}) for
	 *  which to return the list.
	 * @param offset the offset of the symbol (beyond length and symbol type fields); this is the
	 *  offset value specified by many symbol type records.
	 * @return the symbol group for the module or null if not found.
	 * @throws PdbException Upon moduleNumber out of range or no module information.
	 */
	public AbstractMsSymbol getSymbolForModuleAndOffsetOfRecord(int moduleNumber, long offset)
			throws PdbException {
		Map<Long, AbstractMsSymbol> symbols = getModuleSymbolsByOffset(moduleNumber);
		if (symbols == null) {
			return null;
		}
		return symbols.get(offset - 4);
	}

	/**
	 * Returns list of {@link AbstractSectionContribution} for this Database Interface.
	 * @return List of {@link AbstractSectionContribution}.
	 */
	public List<AbstractSectionContribution> getSectionContributionList() {
		return sectionContributionList;
	}

	/**
	 * Returns list of {@link SegmentMapDescription} for this Database Interface.
	 * @return List of {@link SegmentMapDescription}.
	 */
	public List<SegmentMapDescription> getSegmentMapList() {
		return segmentMapList;
	}

	/**
	 * Returns {@link SymbolRecords} component for this Database Interface.
	 * @return {@link SymbolRecords} component.
	 */
	public SymbolRecords getSymbolRecords() {
		return symbolRecords;
	}

	/**
	 * Returns {@link GlobalSymbolInformation} component for this Database Interface.
	 * @return {@link GlobalSymbolInformation} component.
	 */
	public GlobalSymbolInformation getGlobalSymbolInformation() {
		return globalSymbolInformation;
	}

	/**
	 * Returns Public Symbol Information component for
	 * this Database Interface.
	 * @return Public Symbol Information component.
	 */
	public PublicSymbolInformation getPublicSymbolInformation() {
		return publicSymbolInformation;
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Returns the stream number for the GlobalSymbols component.
	 * @return Stream number.
	 */
	int getGlobalSymbolsHashMaybeStreamNumber() {
		return streamNumberGlobalStaticSymbolsHashMaybe;
	}

	/**
	 * Returns the stream number for the PublicStaticSymbols component.
	 * @return Stream number.
	 */
	int getPublicStaticSymbolsHashMaybeStreamNumber() {
		return streamNumberPublicStaticSymbolsHashMaybe;
	}

	/**
	 * Returns the stream number for {@link SymbolRecords} component.
	 * @return Stream number.
	 */
	int getSymbolRecordsStreamNumber() {
		return streamNumberSymbolRecords;
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Deserializes the Header.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void deserializeHeader(PdbByteReader reader) throws PdbException;

	/**
	 * Get the header length in bytes as it appears at offset 0 within the DBI stream
	 * @return DBI header length
	 */
	protected abstract int getHeaderLength();

	/**
	 * Deserializes the SubStreams internal to the Database Interface stream.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected abstract void deserializeInternalSubstreams(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException;

	/**
	 * Deserializes the AdditionalSubstreams components.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected abstract void deserializeAdditionalSubstreams(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException;

	/**
	 * Deserializes/Processes the appropriate {@link AbstractModuleInformation} flavor.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected abstract void processModuleInformation(PdbByteReader reader, TaskMonitor monitor,
			boolean skip) throws PdbException, CancelledException;

	/**
	 * Dumps the Header.  This method is for debugging only.
	 * @param writer {@link Writer} to which to write the debug dump.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	protected abstract void dumpHeader(Writer writer) throws IOException;

	/**
	 * Dumps the Internal Substreams.  This method is for debugging only.
	 * @param writer {@link Writer} to which to write the debug dump.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	protected abstract void dumpInternalSubstreams(Writer writer) throws IOException;

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Deserializes/Processes the SectionContributions component.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected void processSectionContributions(PdbByteReader reader, TaskMonitor monitor,
			boolean skip) throws PdbException, CancelledException {
		if (lengthSectionContributionSubstream == 0) {
			return;
		}
		if (skip) {
			reader.skip(lengthSectionContributionSubstream);
			return;
		}
		PdbByteReader substreamReader =
			reader.getSubPdbByteReader(lengthSectionContributionSubstream);
		//System.out.println(substreamReader.dump(0x200));
		long version = substreamReader.parseUnsignedIntVal();
		if (version == SCV1400) {
			//long version2 = substreamReader.parseUnsignedIntVal();
			while (substreamReader.hasMore()) {
				monitor.checkCanceled();
				AbstractSectionContribution sectionContribution = new SectionContribution1400();
				sectionContribution.deserialize(substreamReader);
				sectionContributionList.add(sectionContribution);
			}
		}
		else if (version == SCV600) {
			//long version2 = substreamReader.parseUnsignedIntVal();
			while (substreamReader.hasMore()) {
				monitor.checkCanceled();
				AbstractSectionContribution sectionContribution = new SectionContribution600();
				sectionContribution.deserialize(substreamReader);
				sectionContributionList.add(sectionContribution);
			}
		}
		//TODO: Don't know when SectionContribution200 is the type to use.  Don't know if
		// this part could be the default of processSectionContribs within
		// DebugInfo and if the above part (test for SVC600 and SVC1400 would
		// be the override method for DatabaseInformationNew.
		else {
			while (substreamReader.hasMore()) {
				monitor.checkCanceled();
				AbstractSectionContribution sectionContribution = new SectionContribution400();
				sectionContribution.deserialize(substreamReader);
				sectionContributionList.add(sectionContribution);
			}
		}
	}

	/**
	 * Deserializes/Processes the {@link SegmentMapDescription}.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	// TODO: unused value numSegLog?
	// Note: this is SegmentMap or SectionMap (API structs are segment; API code is Section)
	// Suppress "unused" for numSegLog
	@SuppressWarnings("unused")
	protected void processSegmentMap(PdbByteReader reader, TaskMonitor monitor, boolean skip)
			throws PdbException, CancelledException {
		if (lengthSectionMap == 0) {
			return;
		}
		if (skip) {
			reader.skip(lengthSectionMap);
			return;
		}
		PdbByteReader substreamReader = reader.getSubPdbByteReader(lengthSectionMap);
		//System.out.println(substreamReader.dump(0x200));
		// Process header
		int numSegments = substreamReader.parseUnsignedShortVal();
		int numSegLog = substreamReader.parseUnsignedShortVal();
		// Process records
		while (substreamReader.hasMore()) {
			monitor.checkCanceled();
			SegmentMapDescription segment = new SegmentMapDescription();
			segment.deserialize(substreamReader);
			segmentMapList.add(segment);
		}
		if (numSegments != segmentMapList.size()) {
			throw new PdbException("numSegments != segmentMapList.size()");
		}
	}

	/**
	 * Deserializes/Processes the FileInformation.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException upon error parsing filename.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected void processFileInformation(PdbByteReader reader, TaskMonitor monitor, boolean skip)
			throws PdbException, CancelledException {
		if (lengthFileInformation == 0) {
			return;
		}
		if (skip) {
			reader.skip(lengthFileInformation);
			return;
		}
		PdbByteReader fileInfoReader = reader.getSubPdbByteReader(lengthFileInformation);

		int numInformationModules = fileInfoReader.parseUnsignedShortVal();
		if (numInformationModules != moduleInformationList.size()) {
			throw new PdbException("Corrupt numInformationModules");
		}
		int numRefs = fileInfoReader.parseUnsignedShortVal();

		PdbByteReader indicesReader = fileInfoReader.getSubPdbByteReader(numInformationModules * 2);
		PdbByteReader countsReader = fileInfoReader.getSubPdbByteReader(numInformationModules * 2);

		int[] index = new int[numInformationModules];
		int[] count = new int[numInformationModules];
		int totalCount = 0;
		for (int moduleIndex = 0; moduleIndex < numInformationModules; moduleIndex++) {
			monitor.checkCanceled();
			index[moduleIndex] = indicesReader.parseUnsignedShortVal();
			count[moduleIndex] = countsReader.parseUnsignedShortVal();
			totalCount += count[moduleIndex];
		}

		if (totalCount != numRefs) {
			PdbLog.message("totalRefs != numRefs, using totalRefs");
		}
		int previousIndex = totalCount;
		for (int moduleIndex = numInformationModules - 1; moduleIndex >= 0; moduleIndex--) {
			monitor.checkCanceled();
			int numFilesContributing = previousIndex - index[moduleIndex];
			previousIndex = index[moduleIndex];
			AbstractModuleInformation module = moduleInformationList.get(moduleIndex);
			module.setNumFilesContributing(numFilesContributing);
		}

		PdbByteReader offsetReader = fileInfoReader.getSubPdbByteReader(totalCount * 4);
		int[] offset = new int[totalCount];
		for (int moduleIndex = 0; moduleIndex < totalCount; moduleIndex++) {
			offset[moduleIndex] = offsetReader.parseInt();
		}
		PdbByteReader namesReader =
			fileInfoReader.getSubPdbByteReader(fileInfoReader.numRemaining());

		int totalRefs = 0;
		for (int moduleIndex = 0; moduleIndex < numInformationModules; moduleIndex++) {
			AbstractModuleInformation module = moduleInformationList.get(moduleIndex);
			for (int fileIndex = 0; fileIndex < count[moduleIndex]; fileIndex++) {
				int ref = totalRefs + fileIndex;
				int nameOffset = offset[ref];
				namesReader.setIndex(nameOffset);
				String filename = parseFileInfoName(namesReader);
				module.addFilenameByOffset(nameOffset, filename);
			}
			totalRefs += count[moduleIndex];
		}
	}

	/**
	 * Method to parse the filename for the "File Information" section from the
	 * {@link PdbByteReader}.
	 * @param reader the {@link PdbByteReader} from which to parse the data
	 * @return the filename
	 * @throws PdbException upon error parsing the filename
	 */
	protected abstract String parseFileInfoName(PdbByteReader reader) throws PdbException;

	/**
	 * Debug method for dumping information from this {@link PdbDebugInfo}-based
	 *  instance.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dump(Writer writer) throws IOException {
		writer.write("DebugInfoHeader---------------------------------------------\n");
		dumpHeader(writer);
		writer.write("\nEnd DebugInfoHeader-----------------------------------------\n");
		writer.write("DebugInfoInternalSubstreams---------------------------------\n");
		dumpInternalSubstreams(writer);
		writer.write("\nEnd DebugInfoInternalSubstreams-----------------------------\n");
		writer.write("DebugInfoAdditionalSubstreams-------------------------------\n");
		dumpAdditionalSubstreams(writer);
		writer.write("\nEnd DebugInfoAdditionalSubstreams---------------------------\n");
	}

	/**
	 * Debug method for dumping additional substreams from this
	 *  {@link PdbDebugInfo}-based instance.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dumpAdditionalSubstreams(Writer writer) throws IOException {
		symbolRecords.dump(writer);
		writer.write("\n");
		globalSymbolInformation.dump(writer);
		writer.write("\n");
		publicSymbolInformation.dump(writer);
	}

	/**
	 * Debug method for dumping module information for all of the {@link AbstractModuleInformation}
	 *  modules from this {@link PdbDebugInfo}-based instance.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dumpModuleInformation(Writer writer) throws IOException {
		for (AbstractModuleInformation information : moduleInformationList) {
			writer.write(information.dump());
			writer.write("\n");
		}
	}

	/**
	 * Debug method for dumping section contribution for all of the
	 *  {@link AbstractSectionContribution} components from this
	 * {@link PdbDebugInfo}-based instance.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dumpSectionContributions(Writer writer) throws IOException {
		for (AbstractSectionContribution contribution : sectionContributionList) {
			writer.write(contribution.dump());
			writer.write("\n");
		}
	}

	/**
	 * Debug method for dumping segment map information for all of the
	 *  {@link SegmentMapDescription} components from this {@link PdbDebugInfo}-based
	 *  instance.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dumpSegmentMap(Writer writer) throws IOException {
		for (SegmentMapDescription description : segmentMapList) {
			writer.write(description.dump());
			writer.write("\n");
		}
	}

}
