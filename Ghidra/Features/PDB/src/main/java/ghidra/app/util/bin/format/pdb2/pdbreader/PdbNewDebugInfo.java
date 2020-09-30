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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class is the version of {@link PdbDebugInfo} for newer PDB files.
 * <P>
 * This class uses {@link ModuleInformation600}.
 */
public class PdbNewDebugInfo extends PdbDebugInfo {

	//==============================================================================================
	// Internals
	//==============================================================================================
	private static final long HEADER_MAGIC = 0xeffeeffeL;
	private static final int DBI_HEADER_LENGTH = 64;

	protected Hasher hasher; //Might belong in parent?  Used in parent (even older Hasher?)

	// The source of these values can overlay other fields in older versions of this type.
	protected long versionSignature = 0; // unsigned 32-bit 

	protected long dbiAge = 0; // unsigned 32-bit
	protected int universalVersion = 0; // unsigned 16-bit
	protected int pdbDllBuildVersion = 0; // unsigned 16-bit
	protected int pdbDllReleaseBuildVersion = 0; // unsigned 16-bit

	protected int lengthTypeServerMapSubstream = 0; // signed 32-bit
	protected long indexOfMicrosoftFoundationClassTypeServer = 0; // unsigned 32-bit
	protected int lengthOptionalDebugHeader = 0; // signed 32-bit
	protected int lengthEditAndContinueSubstream = 0; // signed 32-bit

	protected int flags = 0; // unsigned 16-bit
	protected ImageFileMachine machineType; // parsed unsigned 16-bit and interpreted.
	protected long padReserve = 0; // unsigned 32-bit

	protected List<String> editAndContinueNameList = new ArrayList<>();
	protected List<Integer> debugStreamList = new ArrayList<>(); // TODO: this is a guess.
	protected DebugData debugData;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns this {@link PdbNewDebugInfo}.
	 * @param streamNumber The stream number that contains the {@link PdbNewDebugInfo} data.
	 */
	public PdbNewDebugInfo(AbstractPdb pdb, int streamNumber) {
		super(pdb, streamNumber);
		debugData = new DebugData(pdb);
	}

	/**
	 * Returns the {@link ImageFileMachine} machine type.
	 * @return the machine type.
	 */
	public ImageFileMachine getMachineType() {
		return machineType;
	}

	/**
	 * Returns the {@link DebugData} for this {@link PdbNewDebugInfo}.
	 * @return the {@link DebugData}.
	 */
	public DebugData getDebugData() {
		return debugData;
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	protected void deserializeHeader(PdbByteReader reader) throws PdbException {
		//System.out.println(reader.dump(0x200));
		versionSignature = reader.parseUnsignedIntVal();
		versionNumber = reader.parseUnsignedIntVal();
		dbiAge = reader.parseUnsignedIntVal();

		streamNumberGlobalStaticSymbolsHashMaybe = reader.parseUnsignedShortVal();

		// Has bit-fields that could be broken out further
		universalVersion = reader.parseUnsignedShortVal();

		streamNumberPublicStaticSymbolsHashMaybe = reader.parseUnsignedShortVal();
		pdbDllBuildVersion = reader.parseUnsignedShortVal();

		streamNumberSymbolRecords = reader.parseUnsignedShortVal();
		pdbDllReleaseBuildVersion = reader.parseUnsignedShortVal();

		lengthModuleInformationSubstream = reader.parseInt();
		lengthSectionContributionSubstream = reader.parseInt();
		lengthSectionMap = reader.parseInt();
		lengthFileInformation = reader.parseInt();
		lengthTypeServerMapSubstream = reader.parseInt();
		indexOfMicrosoftFoundationClassTypeServer = reader.parseUnsignedIntVal();
		lengthOptionalDebugHeader = reader.parseInt();
		lengthEditAndContinueSubstream = reader.parseInt();

		flags = reader.parseUnsignedShortVal();
		machineType = ImageFileMachine.fromValue(reader.parseUnsignedShortVal());
		padReserve = reader.parseUnsignedIntVal();

		// update PDB with age and processor
		pdb.setTargetProcessor(machineType.getProcessor());
		pdb.setDbiAge((int) dbiAge);
	}

	@Override
	protected int getHeaderLength() {
		return DBI_HEADER_LENGTH;
	}

	@Override
	protected void deserializeInternalSubstreams(PdbByteReader reader, TaskMonitor monitor)
			throws PdbException, CancelledException {
		processModuleInformation(reader, monitor, false);
		processSectionContributions(reader, monitor, false);
		processSegmentMap(reader, monitor, false);
		processFileInformation(reader, monitor, false);
		processTypeServerMap(reader, false);
		//Note that the next two are in reverse order from their length fields in the header.
		processEditAndContinueInformation(reader, monitor, false);
		//processDebugHeader(reader, false);
		debugData.deserializeHeader(reader, monitor);
	}

	@Override
	protected void deserializeAdditionalSubstreams(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		// TODO: evaluate.  I don't think we need GlobalSymbolInformation (hash) or the
		//  PublicSymbolInformation (hash), as they are both are search mechanisms. 
		symbolRecords.deserialize(monitor);
		globalSymbolInformation.deserialize(getGlobalSymbolsHashMaybeStreamNumber(), monitor);
		publicSymbolInformation.deserialize(getPublicStaticSymbolsHashMaybeStreamNumber(), monitor);
		//TODO: Process further information that might be found from ProcessTypeServerMap,
		// and processEditAndContinueInformation.
		debugData.deserialize(monitor);
	}

	@Override
	protected void processModuleInformation(PdbByteReader reader, TaskMonitor monitor, boolean skip)
			throws PdbException, CancelledException {
		if (lengthModuleInformationSubstream == 0) {
			return;
		}
		if (skip) {
			reader.skip(lengthModuleInformationSubstream);
			return;
		}
		PdbByteReader substreamReader =
			reader.getSubPdbByteReader(lengthModuleInformationSubstream);
		while (substreamReader.hasMore()) {
			monitor.checkCanceled();
			AbstractModuleInformation moduleInformation = new ModuleInformation600(pdb);
			moduleInformation.deserialize(substreamReader);
			moduleInformationList.add(moduleInformation);
		}
	}

	@Override
	protected String parseFileInfoName(PdbByteReader reader) throws PdbException {
		// Totally guessing that this is the correct type of string here.
		String filename = reader.parseString(pdb, StringParseType.StringNt);
		return filename;
	}

	@Override
	protected void dumpHeader(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("versionSignature: ");
		builder.append(versionSignature);
		builder.append("\nversionNumber: ");
		builder.append(versionNumber);
		builder.append("\nage: ");
		builder.append(dbiAge);
		builder.append("\nstreamNumberGlobalStaticSymbols: ");
		builder.append(streamNumberGlobalStaticSymbolsHashMaybe);
		builder.append(String.format("\nuniversalVersion: 0x%04x", universalVersion));
		builder.append("\nstreamNumberPublicStaticSymbols: ");
		builder.append(streamNumberPublicStaticSymbolsHashMaybe);
		builder.append(String.format("\npdbDllBuildVersion: 0x%04x", pdbDllBuildVersion));
		builder.append("\nstreamNumberSymbolRecords: ");
		builder.append(streamNumberSymbolRecords);
		builder.append(
			String.format("\npdbDllReleaseBuildVersion: 0x%04x", pdbDllReleaseBuildVersion));
		builder.append("\nlengthModuleInformationSubstream: ");
		builder.append(lengthModuleInformationSubstream);
		builder.append("\nlengthSectionContributionSubstream: ");
		builder.append(lengthSectionContributionSubstream);
		builder.append("\nlengthSectionMap: ");
		builder.append(lengthSectionMap);
		builder.append("\nlengthFileInformation: ");
		builder.append(lengthFileInformation);

		builder.append("\nlengthTypeServerMapSubstream: ");
		builder.append(lengthTypeServerMapSubstream);
		builder.append("\nindexOfMicrosoftFoundationClassTypeServer: ");
		builder.append(indexOfMicrosoftFoundationClassTypeServer);
		builder.append("\nlengthOptionalDebugHeader: ");
		builder.append(lengthOptionalDebugHeader);
		builder.append("\nlengthEditAndContinueSubstream: ");
		builder.append(lengthEditAndContinueSubstream);
		builder.append(String.format("\nflags: 0x%04x", flags));
		builder.append(String.format("\nmachineType: %s", machineType.toString()));
		builder.append("\npadReserve: ");
		builder.append(padReserve);
		writer.write(builder.toString());
	}

	@Override
	protected void dumpInternalSubstreams(Writer writer) throws IOException {
		writer.write("ModuleInformationList---------------------------------------\n");
		dumpModuleInformation(writer);
		writer.write("\nEnd ModuleInformationList-----------------------------------\n");
		writer.write("SectionContributionList-------------------------------------\n");
		dumpSectionContributions(writer);
		writer.write("\nEnd SectionContributionList---------------------------------\n");
		writer.write("SegmentMap--------------------------------------------------\n");
		dumpSegmentMap(writer);
		writer.write("\nEnd SegmentMap----------------------------------------------\n");
		writer.write("EditAndContinueNameList-------------------------------------\n");
		dumpEditAndContinueNameList(writer);
		writer.write("\nEnd EditAndContinueNameList---------------------------------\n");
		debugData.dump(writer);
	}

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	//TODO: Find examples that exercise this.
	/**
	 * Deserializes/Processes the TypeServerMap.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	@SuppressWarnings("unused") // substreamReader
	protected void processTypeServerMap(PdbByteReader reader, boolean skip) throws PdbException {
		if (lengthTypeServerMapSubstream == 0) {
			return;
		}
		if (skip) {
			reader.skip(lengthTypeServerMapSubstream);
			return;
		}
		PdbByteReader substreamReader = reader.getSubPdbByteReader(lengthTypeServerMapSubstream);
		//System.out.println(sumbstreamReader.dump(0x1000));
	}

	/**
	 * Deserializes/Processes the EditAndContinueInformation.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @param skip Skip over the data in the {@link PdbByteReader}.
	 * @throws PdbException upon error parsing a name or unexpected data.
	 * @throws CancelledException Upon user cancellation.
	 */
	@SuppressWarnings("unused") // hashVal
	protected void processEditAndContinueInformation(PdbByteReader reader, TaskMonitor monitor,
			boolean skip) throws PdbException, CancelledException {
		if (lengthEditAndContinueSubstream == 0) {
			return;
		}
		if (skip) {
			reader.skip(lengthEditAndContinueSubstream);
			return;
		}
		PdbByteReader substreamReader = reader.getSubPdbByteReader(lengthEditAndContinueSubstream);
		//System.out.println(substreamReader.dump(0x1000));
		long hdr = substreamReader.parseUnsignedIntVal();
		int ver = substreamReader.parseInt(); // spec says unsigned, but I believe small vals.
		if (hdr != HEADER_MAGIC) {
			return; //For now... we are not going to try to populate this with a conversion.
		}
		switch (ver) {
			case 1:
				hasher = new Hasher32();
				break;
			case 2:
				hasher = new Hasher32V2();
				break;
			case 0: // Maybe should use Hasher()???
			default:
				return;
		}
		int length = substreamReader.parseInt();
		PdbByteReader bufferReader = substreamReader.getSubPdbByteReader(length);
		//System.out.println(bufferReader.dump());
		int tableSize = substreamReader.parseInt();
		int count = tableSize;
		int realEntryCount = 0;
		while (--count >= 0) {
			monitor.checkCanceled();
			int offset = substreamReader.parseInt();
			bufferReader.setIndex(offset);
			String name = bufferReader.parseNullTerminatedString(
				pdb.getPdbReaderOptions().getOneByteCharset());
			//if (name != null) {
			if (name.length() != 0) {
				realEntryCount++;
			}
			editAndContinueNameList.add(name);
			//long hashVal = (name == null) ? 0 : hasher.hash(name, 0xffffffffL);
			long hashVal = (name.length() == 0) ? 0 : hasher.hash(name, 0xffffffffL);
			hashVal %= tableSize;
			//TODO: what to do with hashVal???
			//System.out.println(offset + ": " + name + " " + hashVal);
		}
		int numRealEntries = substreamReader.parseInt();
		if (realEntryCount != numRealEntries) {
			throw new PdbException("Count mismatch: " + realEntryCount + " vs. " + numRealEntries);
		}
	}

	/**
	 * Dumps the EditAndContinueNameList.  This package-protected method is for debugging only.
	 * @param writer {@link Writer} to which to write the debug dump.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	protected void dumpEditAndContinueNameList(Writer writer) throws IOException {
		for (String name : editAndContinueNameList) {
			writer.write(String.format("Name: %s\n", name));
		}
	}

	/**
	 * Get age from deserialized DBI header
	 * @return age from deserialized DBI header
	 */
	long getAge() {
		return dbiAge;
	}

}
