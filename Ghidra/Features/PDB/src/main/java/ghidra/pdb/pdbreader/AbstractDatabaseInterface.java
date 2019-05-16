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
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.Validate;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Database Interface component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public abstract class AbstractDatabaseInterface {

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
	protected int lengthSectionContributionSubstream = 0; // signed 32-bit //TODO: also in parent.
	protected int lengthSectionMap = 0; // signed 32-bit
	protected int lengthFileInformation = 0; // signed 32-bit

	protected List<AbstractModuleInformation> moduleInformationList = new ArrayList<>();
	protected List<AbstractSectionContribution> sectionContributionList = new ArrayList<>();
	protected List<SegmentMapDescription> segmentMapList = new ArrayList<>();

	protected SymbolRecords symbolRecords;
//	protected GlobalSymbolInformation globalSymbolInformation;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns this Database Interface.
	 * @param streamNumber The stream number of the stream containing the Database Interface.
	 */
	public AbstractDatabaseInterface(AbstractPdb pdb, int streamNumber) {
		Validate.notNull(pdb, "pdb cannot be null)");
		this.pdb = pdb;
		this.streamNumber = streamNumber;
//		globalSymbolInformation = new GlobalSymbolInformation(pdb);
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
	 * Deserializes the {@link AbstractDatabaseInterface}-based instance.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @return The version number of the Database Interface.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	public long deserialize(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
		deserializeHeader(reader);
		deserializeInternalSubstreams(reader, monitor);
		deserializeAdditionalSubstreams(monitor);

		return versionNumber;
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
	 * @param moduleNumber The module number being requested.
	 * @return {@link AbstractModuleInformation} for the moduleNumber provided.
	 * @throws PdbException Upon moduleNumber out of range or no module information.
	 */
	public AbstractModuleInformation getModuleInformation(int moduleNumber) throws PdbException {
		if (moduleNumber < 0 || moduleNumber > moduleInformationList.size()) {
			throw new PdbException("ModuleNumber out of range: " + moduleNumber);
		}
		AbstractModuleInformation moduleInfo = moduleInformationList.get(moduleNumber);
		if (moduleInfo == null) {
			throw new PdbException("Null AbstractModuleInformation");
		}
		return moduleInfo;
	}

	/**
	 * Return a comprehensive list of {@link AbstractMsSymbol}s, including from modules.
	 * <P>
	 * <P>
	 * Note: This is Ghidra-added functionality that might eventually go away; it is implemented
	 *  for investigating how to mine the information we need from the PDB. This might go away in
	 *  future implementations.
	 * @return Symbols seen.
	 */
	public List<AbstractMsSymbol> getComprehensiveSymbolsList() {
		return symbolRecords.getComprehensiveSymbolsList();
	}

	/**
	 * Returns a specific {@link AbstractMsSymbol} based on a Ghidra-specific recordNumber
	 *  parameter.  The record number is not part of a normal PDB, but we assigned a one-up
	 *  numbering.
	 * <P>
	 * Note: This is Ghidra-added functionality that might eventually go away; it is implemented
	 *  for investigating how to mine the information we need from the PDB. This might go away in
	 *  future implementations.
	 * @param recordNumber The Ghidra-specific record number for the {@link AbstractMsSymbol}.
	 * @return {@link AbstractMsSymbol} for the recordNumber.
	 */
	public AbstractMsSymbol getComprehensiveSymbolRecord(int recordNumber) {
		return symbolRecords.getComprehensiveSymbolRecord(recordNumber);
	}

	/**
	 * Returns the list of regular {@link AbstractMsSymbol} symbols.
	 * @return Regular {@link AbstractMsSymbol} symbols.
	 */
	public List<AbstractMsSymbol> getSymbolsList() {
		return symbolRecords.getSymbolsList();
	}

	/**
	 * Returns list of {@link AbstractMsSymbol} for the module specified.
	 * @param moduleNumber The number ID of the module for which to return the list.
	 * @return {@link AbstractMsSymbol} symbols in the specified module.
	 */
	public List<AbstractMsSymbol> getModuleSymbolLists(int moduleNumber) {
		return symbolRecords.getModuleSymbolLists(moduleNumber);
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

//	/**
//	 * Returns {@link GlobalSymbolInformation} component for this Database Interface.
//	 * @return {@link GlobalSymbolInformation} component.
//	 */
//	public GlobalSymbolInformation getGlobalSymbolInformation() {
//		return globalSymbolInformation;
//	}

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
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException upon error parsing a field.
	 */
	protected abstract void processModuleInformation(PdbByteReader reader, boolean skip)
			throws PdbException;

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
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected void processSectionContributions(PdbByteReader reader, boolean skip)
			throws PdbException {
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
				AbstractSectionContribution sectionContribution = new SectionContribution1400();
				sectionContribution.deserialize(substreamReader);
				sectionContributionList.add(sectionContribution);
			}
		}
		else if (version == SCV600) {
			//long version2 = substreamReader.parseUnsignedIntVal();
			while (substreamReader.hasMore()) {
				AbstractSectionContribution sectionContribution = new SectionContribution600();
				sectionContribution.deserialize(substreamReader);
				sectionContributionList.add(sectionContribution);
			}
		}
		//TODO: Don't know when SectionContribution200 are the type to use.  Dont' know if
		// this part could be the default of processSectionContribs within
		// DatabaseInterface and if the above part (test for SVC600 and SVC1400 would
		// be the override method for DatabaseInformationNew.
		else {
			while (substreamReader.hasMore()) {
				AbstractSectionContribution sectionContribution = new SectionContribution400();
				sectionContribution.deserialize(substreamReader);
				sectionContributionList.add(sectionContribution);
			}
		}
	}

	// TODO: unused value numSegLog?
	// Note: this is SegmentMap or SectionMap (API structs are segment; API code is Section)
	// Suppress "unused" for numSegLog
	/**
	 * Deserializes/Processes the {@link SegmentMapDescription}.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	@SuppressWarnings("unused")
	protected void processSegmentMap(PdbByteReader reader, boolean skip) throws PdbException {
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
			SegmentMapDescription segment = new SegmentMapDescription();
			segment.deserialize(substreamReader);
			segmentMapList.add(segment);
		}
		if (numSegments != segmentMapList.size()) {
			assert false;
		}
	}

	/**
	 * Deserializes/Processes the FileInformation.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException upon error parsing filename.
	 */
	@SuppressWarnings("unused") // pmod is not used below
	protected void processFileInformation(PdbByteReader reader, boolean skip) throws PdbException {
		if (lengthFileInformation == 0) {
			return;
		}
		if (skip) {
			reader.skip(lengthFileInformation);
			return;
		}
		PdbByteReader substreamReader = reader.getSubPdbByteReader(lengthFileInformation);
		//System.out.println(subStreamReader.dump());
		int numInformationModules = substreamReader.parseUnsignedShortVal();
		if (numInformationModules != moduleInformationList.size()) {
			assert false;
		}
		int numRefs = substreamReader.parseUnsignedShortVal();
		int x = 0;
		for (int i = 0; i < numInformationModules; i++) {
			int refIndex = substreamReader.parseUnsignedShortVal();
			AbstractModuleInformation module = moduleInformationList.get(i);
			int num = module.getNumFilesContributing();
			if (refIndex != x) {
				assert false;
			}
			x += num;
		}
		for (int i = 0; i < numInformationModules; i++) {
			// TODO: Is there anything we can do with this?
			int pmod = substreamReader.parseUnsignedShortVal();
		}
		int count = 0;
		for (int i = 0; i < numInformationModules; i++) {
			AbstractModuleInformation module = moduleInformationList.get(i);
			int num = module.getNumFilesContributing();
			for (int j = 0; j < num; j++) {
				int index = substreamReader.parseInt();
				module.offsetsArray.add(index);
				count++;
			}
		}
		if (count != numRefs) {
			assert false;
		}
		//Following is read in and added to ModuleInformation
		byte[] fileNamesBytes = substreamReader.parseBytesRemaining();
		PdbByteReader fileNameReader = new PdbByteReader(fileNamesBytes);

		//System.out.println(fileNameReader.dump());
		for (int i = 0; i < numInformationModules; i++) {
			AbstractModuleInformation module = moduleInformationList.get(i);
			List<Integer> offsetsArray = module.getOffsetsArray();
			List<String> filenameArray = module.getFilenamesArray();
			for (int j = 0; j < offsetsArray.size(); j++) {
				int offset = offsetsArray.get(j);
				//System.out.println(String.format("%04x", offset));
				fileNameReader.setIndex(offset);
				String filename = fileNameReader.parseNullTerminatedString();
				filenameArray.add(filename);
				//System.out.println(filename);
			}
		}
	}

	/**
	 * Debug method for dumping information from this {@link AbstractDatabaseInterface}-based
	 *  instance.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dump(Writer writer) throws IOException {
		writer.write("DatabaseInterfaceHeader-------------------------------------\n");
		dumpHeader(writer);
		writer.write("\nEnd DatabaseInterfaceHeader---------------------------------\n");
		writer.write("DatabaseInterfaceInternalSubstreams-------------------------\n");
		dumpInternalSubstreams(writer);
		writer.write("\nEnd DatabaseInterfaceInternalSubstreams---------------------\n");
		writer.write("DatabaseInterfaceAdditionalSubstreams-----------------------\n");
		dumpAdditionalSubstreams(writer);
		writer.write("\nEnd DatabaseInterfaceAdditionalSubstreams-------------------\n");
	}

	/**
	 * Debug method for dumping additional substreams from this
	 *  {@link AbstractDatabaseInterface}-based instance.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dumpAdditionalSubstreams(Writer writer) throws IOException {
		symbolRecords.dump(writer);
//		writer.write("\n");
//		globalSymbolInformation.dump(writer);
	}

	/**
	 * Debug method for dumping module information for all of the {@link AbstractModuleInformation}
	 *  modules from this {@link AbstractDatabaseInterface}-based instance.
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
	 * {@link AbstractDatabaseInterface}-based instance.
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
	 *  {@link SegmentMapDescription} components from this {@link AbstractDatabaseInterface}-based
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
