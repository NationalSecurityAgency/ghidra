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

	protected List<ModuleInformation> moduleInformationList = new ArrayList<>();
	protected List<SectionContribution> sectionContributionList = new ArrayList<>();
	protected List<SegmentMapDescription> segmentMapList = new ArrayList<>();

	protected SymbolRecords symbolRecords;
	protected GlobalSymbolInformation globalSymbolInformation;
	protected PublicSymbolInformation publicSymbolInformation;

	//==============================================================================================
	// NEW STUFF FROM REFACTOR/REWORK (can be duplicative with other stuff)... might be turned off
	// during development.
	private boolean doNewStuff = false;
	private List<Module> modules = new ArrayList<>();

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor
	 * @param pdb {@link AbstractPdb} that owns this debug info
	 * @param streamNumber the stream number of the stream containing the debug info
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
	 * Returns the number of bytes needed to store the version number
	 * @return the number of bytes needed to store the version number
	 */
	public static int getVersionNumberSize() {
		return VERSION_NUMBER_SIZE;
	}

	/**
	 * Deserializes the {@link PdbDebugInfo}-based instance.
	 * The PDB is updated with dbiAge and targetProcessor during deserialization
	 * of new DBI header.
	 * @param headerOnly if true only the DBI header fields will be parsed
	 * @return the version number of the debug info
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon error parsing a field
	 * @throws CancelledException upon user cancellation
	 */
	public long deserialize(boolean headerOnly)
			throws IOException, PdbException, CancelledException {
		if (headerOnly) {
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(streamNumber, 0, getHeaderLength());
			deserializeHeader(reader);
		}
		else {
			PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber);
			deserializeHeader(reader);
			deserializeInternalSubstreams(reader);
			deserializeAdditionalSubstreams();
			// BELOW: NEW STUFF FROM REFACTOR/REWORK (can be duplicative with other stuff)
			if (doNewStuff) {
				parseModules();
				compareSymbols(); //temporary to ensure same results with previous work.
			}
			// ABOVE: NEW STUFF FROM REFACTOR/REWORK (can be duplicative with other stuff)
		}
		return versionNumber;
	}

	/**
	 * Returns the number of modules
	 * @return the number of modules
	 */
	public int getNumModules() {
		return moduleInformationList.size();
	}

	/**
	 * Returns the list of {@link ModuleInformation}, indexed by the module number
	 * @return list of {@link ModuleInformation}
	 */
	public List<ModuleInformation> getModuleInformationList() {
		return moduleInformationList;
	}

	/**
	 * Returns the {@link ModuleInformation}, based on the moduleNumber
	 * @param moduleNumber the module number being requested (1 to {@link #getNumModules()})
	 * @return {@link ModuleInformation} for the moduleNumber provided
	 * @throws PdbException upon moduleNumber out of range or no module information
	 */
	public ModuleInformation getModuleInformation(int moduleNumber) throws PdbException {
		if (moduleNumber < 1 || moduleNumber > moduleInformationList.size()) {
			throw new PdbException("ModuleNumber out of range: " + moduleNumber);
		}
		ModuleInformation moduleInfo = moduleInformationList.get(moduleNumber - 1);
		if (moduleInfo == null) {
			throw new PdbException("Null AbstractModuleInformation");
		}
		return moduleInfo;
	}

	/**
	 * Returns the list of combined global/public symbols
	 * @return {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols
	 */
	public Map<Long, AbstractMsSymbol> getSymbolsByOffset() {
		return symbolRecords.getSymbolsByOffset();
	}

	/**
	 * Returns the buffer-offset-to-symbol map for the module as specified by moduleNumber
	 * @param moduleNumber the number ID of the module for which to return the list
	 * @return {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols for the specified module
	 * @throws PdbException upon moduleNumber out of range or no module information
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
	 *  actual symbol record offset (which is past the length and symbol type fields)
	 * @param offset the offset of the symbol (beyond length and symbol type fields); this is the
	 *  offset value specified by many symbol type records
	 * @return the symbol group for the module or null if not found
	 */
	public AbstractMsSymbol getSymbolForOffsetOfRecord(long offset) {
		return getSymbolsByOffset().get(offset - 4);
	}

	/**
	 * Returns the {@link AbstractMsSymbol} for the module as specified by moduleNumber and
	 *  actual symbol record offset (which is past the length and symbol type fields)
	 * @param moduleNumber the number ID of the module (1 to {@link #getNumModules()}) for
	 *  which to return the list
	 * @param offset the offset of the symbol (beyond length and symbol type fields); this is the
	 *  offset value specified by many symbol type records
	 * @return the symbol group for the module or null if not found
	 * @throws PdbException upon moduleNumber out of range or no module information
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
	 * Returns list of {@link SectionContribution} for this debug info
	 * @return list of {@link SectionContribution}
	 */
	public List<SectionContribution> getSectionContributionList() {
		return sectionContributionList;
	}

	/**
	 * Returns list of {@link SegmentMapDescription} for this debug info
	 * @return list of {@link SegmentMapDescription}
	 */
	public List<SegmentMapDescription> getSegmentMapList() {
		return segmentMapList;
	}

	/**
	 * Returns {@link SymbolRecords} component for this debug info
	 * @return {@link SymbolRecords} component
	 */
	public SymbolRecords getSymbolRecords() {
		return symbolRecords;
	}

	/**
	 * Returns {@link GlobalSymbolInformation} component for this debug info
	 * @return {@link GlobalSymbolInformation} component
	 */
	public GlobalSymbolInformation getGlobalSymbolInformation() {
		return globalSymbolInformation;
	}

	/**
	 * Returns Public Symbol Information component for this debug info
	 * @return Public Symbol Information component
	 */
	public PublicSymbolInformation getPublicSymbolInformation() {
		return publicSymbolInformation;
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Returns the stream number for the GlobalSymbols component
	 * @return stream number
	 */
	int getGlobalSymbolsHashMaybeStreamNumber() {
		return streamNumberGlobalStaticSymbolsHashMaybe;
	}

	/**
	 * Returns the stream number for the PublicStaticSymbols component
	 * @return stream number
	 */
	int getPublicStaticSymbolsHashMaybeStreamNumber() {
		return streamNumberPublicStaticSymbolsHashMaybe;
	}

	/**
	 * Returns the stream number for {@link SymbolRecords} component
	 * @return stream number
	 */
	int getSymbolRecordsStreamNumber() {
		return streamNumberSymbolRecords;
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Deserializes the Header
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @throws PdbException upon not enough data left to parse
	 */
	protected abstract void deserializeHeader(PdbByteReader reader) throws PdbException;

	/**
	 * Get the header length in bytes as it appears at offset 0 within the DBI stream
	 * @return DBI header length
	 */
	protected abstract int getHeaderLength();

	/**
	 * Deserializes the SubStreams internal to the debug info stream
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @throws PdbException upon error parsing a field
	 * @throws CancelledException upon user cancellation
	 */
	protected abstract void deserializeInternalSubstreams(PdbByteReader reader)
			throws PdbException, CancelledException;

	/**
	 * Deserializes the AdditionalSubstreams components
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon error parsing a field
	 * @throws CancelledException upon user cancellation
	 */
	protected abstract void deserializeAdditionalSubstreams()
			throws IOException, PdbException, CancelledException;

	/**
	 * Deserializes/processes the appropriate {@link ModuleInformation} flavor
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @param skip skip over the data in the {@link PdbByteReader}
	 * @throws PdbException upon error parsing a field
	 * @throws CancelledException upon user cancellation
	 */
	protected abstract void processModuleInformation(PdbByteReader reader, boolean skip)
			throws PdbException, CancelledException;

	/**
	 * Dumps the Header.  This method is for debugging only
	 * @param writer {@link Writer} to which to write the debug dump
	 * @throws IOException on issue writing to the {@link Writer}
	 */
	protected abstract void dumpHeader(Writer writer) throws IOException;

	/**
	 * Dumps the Internal Substreams.  This method is for debugging only
	 * @param writer {@link Writer} to which to write the debug dump
	 * @throws IOException on issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 */
	protected abstract void dumpInternalSubstreams(Writer writer)
			throws IOException, CancelledException;

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Deserializes/processes the SectionContributions component
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @param skip skip over the data in the {@link PdbByteReader}
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	protected void processSectionContributions(PdbByteReader reader, boolean skip)
			throws PdbException, CancelledException {
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
				pdb.checkCancelled();
				SectionContribution sectionContribution = new SectionContribution1400();
				sectionContribution.deserialize(substreamReader);
				sectionContributionList.add(sectionContribution);
			}
		}
		else if (version == SCV600) {
			//long version2 = substreamReader.parseUnsignedIntVal();
			while (substreamReader.hasMore()) {
				pdb.checkCancelled();
				SectionContribution sectionContribution = new SectionContribution600();
				sectionContribution.deserialize(substreamReader);
				sectionContributionList.add(sectionContribution);
			}
		}
		//TODO: Don't know when SectionContribution200 is the type to use.  Don't know if
		// this part could be the default of processSectionContribs within
		// DebugInfo and if the above part (test for SVC600 and SVC1400 would
		// be the override method for PdbNewDebugInfo.
		else {
			while (substreamReader.hasMore()) {
				pdb.checkCancelled();
				SectionContribution sectionContribution = new SectionContribution400();
				sectionContribution.deserialize(substreamReader);
				sectionContributionList.add(sectionContribution);
			}
		}
	}

	/**
	 * Deserializes/processes the {@link SegmentMapDescription}
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @param skip skip over the data in the {@link PdbByteReader}
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	// TODO: unused value numSegLog?
	// Note: this is SegmentMap or SectionMap (API structs are segment; API code is Section)
	// Suppress "unused" for numSegLog
	@SuppressWarnings("unused")
	protected void processSegmentMap(PdbByteReader reader, boolean skip)
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
			pdb.checkCancelled();
			SegmentMapDescription segment = new SegmentMapDescription();
			segment.deserialize(substreamReader);
			segmentMapList.add(segment);
		}
		if (numSegments != segmentMapList.size()) {
			throw new PdbException("numSegments != segmentMapList.size()");
		}
	}

	/**
	 * Deserializes/processes the FileInformation
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @param skip skip over the data in the {@link PdbByteReader}
	 * @throws PdbException upon error parsing filename
	 * @throws CancelledException upon user cancellation
	 */
	protected void processFileInformation(PdbByteReader reader, boolean skip)
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
			pdb.checkCancelled();
			index[moduleIndex] = indicesReader.parseUnsignedShortVal();
			count[moduleIndex] = countsReader.parseUnsignedShortVal();
			totalCount += count[moduleIndex];
		}

		if (totalCount != numRefs) {
			PdbLog.message("totalRefs != numRefs, using totalRefs");
		}

		PdbByteReader offsetReader = fileInfoReader.getSubPdbByteReader(totalCount * 4);
		int[] offset = new int[totalCount];
		for (int moduleIndex = 0; moduleIndex < totalCount; moduleIndex++) {
			pdb.checkCancelled();
			offset[moduleIndex] = offsetReader.parseInt();
		}
		PdbByteReader namesReader =
			fileInfoReader.getSubPdbByteReader(fileInfoReader.numRemaining());

		int totalRefs = 0;
		for (int moduleIndex = 0; moduleIndex < numInformationModules; moduleIndex++) {
			pdb.checkCancelled();
			ModuleInformation module = moduleInformationList.get(moduleIndex);
			for (int fileIndex = 0; fileIndex < count[moduleIndex]; fileIndex++) {
				pdb.checkCancelled();
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
	 * {@link PdbByteReader}
	 * @param reader the {@link PdbByteReader} from which to parse the data
	 * @return the filename
	 * @throws PdbException upon error parsing the filename
	 */
	protected abstract String parseFileInfoName(PdbByteReader reader) throws PdbException;

	/**
	 * Debug method for dumping information from this {@link PdbDebugInfo}-based
	 *  instance
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException upon IOException writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	protected void dump(Writer writer) throws IOException, CancelledException, PdbException {
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
	 * Debug method for dumping additional substreams from this {@link PdbDebugInfo}-based instance
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException upon IOException writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	protected void dumpAdditionalSubstreams(Writer writer)
			throws IOException, CancelledException, PdbException {
		symbolRecords.dump(writer);
		writer.write("\n");
		globalSymbolInformation.dump(writer);
		writer.write("\n");
		publicSymbolInformation.dump(writer);
		if (doNewStuff) {
			dumpSymbols(writer);
			for (Module module : modules) {
				pdb.checkCancelled();
				module.dump(writer);
			}
		}
	}

	/**
	 * Debug method for dumping module information for all of the {@link ModuleInformation}
	 *  modules from this {@link PdbDebugInfo}-based instance
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException upon IOException writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 */
	protected void dumpModuleInformation(Writer writer) throws IOException, CancelledException {
		for (ModuleInformation information : moduleInformationList) {
			pdb.checkCancelled();
			writer.write(information.dump());
			writer.write("\n");
		}
	}

	/**
	 * Debug method for dumping section contribution for all of the
	 * {@link SectionContribution} components from this {@link PdbDebugInfo}-based instance
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException upon IOException writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 */
	protected void dumpSectionContributions(Writer writer) throws IOException, CancelledException {
		for (SectionContribution contribution : sectionContributionList) {
			pdb.checkCancelled();
			writer.write(contribution.dump());
			writer.write("\n");
		}
	}

	/**
	 * Debug method for dumping segment map information for all of the
	 *  {@link SegmentMapDescription} components from this {@link PdbDebugInfo}-based instance
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException upon IOException writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 */
	protected void dumpSegmentMap(Writer writer) throws IOException, CancelledException {
		for (SegmentMapDescription description : segmentMapList) {
			pdb.checkCancelled();
			writer.write(description.dump());
			writer.write("\n");
		}
	}

	//==============================================================================================
	// NEW STUFF FROM REFACTOR/REWORK (can be duplicative with other stuff)... might be turned off
	// during development.
	private void parseModules() throws CancelledException {
		for (ModuleInformation moduleInformation : moduleInformationList) {
			pdb.checkCancelled();
			Module module = new Module(pdb, moduleInformation);
			modules.add(module);
		}
	}

	private int numModules() {
		return modules.size();
	}

	/**
	 * Return the Module based upon the module number
	 * @param moduleNum the module number
	 * @return the module
	 */
	public Module getModule(int moduleNum) {
		return modules.get(moduleNum);
	}

	// NOTE: Designs are not done regarding possibly iterators for iterating only globals or publics
	/**
	 * Returns the symbol iterator for general (public and global symbols
	 * @return an iterator over all symbols of the module
	 * @throws CancelledException upon user cancellation
	 * @throws IOException upon issue reading the stream
	 */
	public MsSymbolIterator getSymbolIterator()
			throws CancelledException, IOException {
		if (streamNumberSymbolRecords == 0xffff) {
			return null;
		}
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumberSymbolRecords);
		MsSymbolIterator iterator = new MsSymbolIterator(pdb, reader);
		return iterator;
	}

	/**
	 * Returns the symbol iterator symbols of the specified module
	 * @param moduleNum the module number
	 * @return an iterator over all symbols of the module
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	MsSymbolIterator getSymbolIterator(int moduleNum) throws CancelledException, PdbException {
		Module module = modules.get(moduleNum);
		return module.getSymbolIterator();
	}

	private void dumpSymbols(Writer writer) throws CancelledException, IOException {
		MsSymbolIterator iterator = getSymbolIterator();
		List<AbstractMsSymbol> symbols = new ArrayList<>();
		while (iterator.hasNext()) {
			pdb.checkCancelled();
			symbols.add(iterator.next());
		}
	}

	// This method is temporary.  It only exists for ensuring results as we transition processing
	// mechanisms.
	private void compareSymbols()
			throws CancelledException, PdbException, IOException {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}

		// Compare general symbols
		MsSymbolIterator iterator = getSymbolIterator();
		List<AbstractMsSymbol> symbols = new ArrayList<>();
		while (iterator.hasNext()) {
			pdb.checkCancelled();
			symbols.add(iterator.next());
		}
		if (symbols.size() != symbolRecords.getSymbolsByOffset().size()) {
			// Set break-point on next line.  Multiple lines here to eliminate Eclipse warning.
			int a = 1;
			a = a + 1;
		}
		int cnt = 0;
		for (Map.Entry<Long, AbstractMsSymbol> entry : symbolRecords.getSymbolsByOffset()
				.entrySet()) {
			pdb.checkCancelled();
			AbstractMsSymbol msym = entry.getValue();
			AbstractMsSymbol lsym = symbols.get(cnt);
			String mstr = msym.toString();
			String lstr = lsym.toString();
			if (!mstr.equals(lstr)) {
				// Set break-point on next line.  Multiple lines here to eliminate Eclipse warning.
				int b = 1;
				b = b + 1;
			}
			cnt++;
		}

		// Compare module symbols
		for (int modnum = 0; modnum < numModules(); modnum++) {
			pdb.checkCancelled();
			Module module = modules.get(modnum);
			MsSymbolIterator moduleSymbolsIterator = module.getSymbolIterator();
			cnt = 0;
			Map<Long, AbstractMsSymbol> map = symbolRecords.getModuleSymbolsByOffset(modnum);
			List<Long> keys = new ArrayList<>();
			for (Map.Entry<Long, AbstractMsSymbol> entry : map.entrySet()) {
				pdb.checkCancelled();
				Long key = entry.getKey();
				keys.add(key);
			}
			Collections.sort(keys);
			for (Long key : keys) {
				pdb.checkCancelled();
				AbstractMsSymbol msym = map.get(key);
				if (!moduleSymbolsIterator.hasNext()) {
					// Set break-point on next line.  Multiple lines here to eliminate Eclipse warning.
					int c = 1;
					c = c + 1;
					break;
				}
				AbstractMsSymbol lsym = moduleSymbolsIterator.next();
				String mstr = msym.toString();
				String lstr = lsym.toString();
				if (!mstr.equals(lstr)) {
					// Set break-point on next line.  Multiple lines here to eliminate Eclipse warning.
					int b = 1;
					b = b + 1;
				}
				cnt++;
			}
			if (moduleSymbolsIterator.hasNext()) {
				// Set break-point on next line.  Multiple lines here to eliminate Eclipse warning.
				int d = 1;
				d = d + 1;
			}
		}
	}
}
