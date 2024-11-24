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

import ghidra.util.exception.CancelledException;

/**
 * This class is the version of {@link PdbDebugInfo} for older PDB files.
 * <P>
 * This class uses {@link ModuleInformation500}.
 */
public class PdbOldDebugInfo extends PdbDebugInfo {

	private static final int OLD_DBI_HEADER_LENGTH = 24;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor
	 * @param pdb {@link AbstractPdb} that owns this {@link PdbOldDebugInfo}
	 * @param streamNumber the number of the stream that contains the {@link PdbOldDebugInfo}
	 */
	public PdbOldDebugInfo(AbstractPdb pdb, int streamNumber) {
		super(pdb, streamNumber);
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	protected void deserializeHeader(PdbByteReader reader) throws PdbException {
		streamNumberGlobalStaticSymbolsHashMaybe = reader.parseUnsignedShortVal();
		streamNumberPublicStaticSymbolsHashMaybe = reader.parseUnsignedShortVal();
		streamNumberSymbolRecords = reader.parseUnsignedShortVal();
		reader.skip(2); // padding between previous unsigned short and next-to-read int
		lengthModuleInformationSubstream = reader.parseInt();
		lengthSectionContributionSubstream = reader.parseInt();
		lengthSectionMap = reader.parseInt();
		lengthFileInformation = reader.parseInt();
	}

	@Override
	protected int getHeaderLength() {
		return OLD_DBI_HEADER_LENGTH;
	}

	@Override
	protected void deserializeInternalSubstreams(PdbByteReader reader)
			throws PdbException, CancelledException {
		processModuleInformation(reader, false);
		processSectionContributions(reader, false);
		processSegmentMap(reader, false);
		processFileInformation(reader, false);
	}

	@Override
	protected void initializeAdditionalComponentsForSubstreams()
			throws IOException, PdbException, CancelledException {
		// TODO: evaluate.  I don't think we need GlobalSymbolInformation (hash) or the
		//  PublicSymbolInformation (hash), as they are both are search mechanisms.
		symbolRecords.initialize();
		globalSymbolInformation.initialize();
		publicSymbolInformation.initialize();
		//TODO: SectionContributions has information about code sections and refers to
		// debug streams for each.
	}

	@Override
	protected void processModuleInformation(PdbByteReader reader, boolean skip)
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
			pdb.checkCancelled();
			ModuleInformation moduleInformation = new ModuleInformation500(pdb);
			moduleInformation.deserialize(substreamReader);
			moduleInformationList.add(moduleInformation);
		}
	}

	@Override
	protected String parseFileInfoName(PdbByteReader reader) throws PdbException {
		String filename = reader.parseString(pdb, StringParseType.StringSt);
		return filename;
	}

	@Override
	protected void dumpHeader(Writer writer) throws IOException {
		StringBuilder builder = new StringBuilder();
		builder.append("streamNumberGlobalStaticSymbols: ");
		builder.append(streamNumberGlobalStaticSymbolsHashMaybe);
		builder.append("\nstreamNumberPublicStaticSymbols: ");
		builder.append(streamNumberPublicStaticSymbolsHashMaybe);
		builder.append("\nstreamNumberSymbolRecords: ");
		builder.append(streamNumberSymbolRecords);
		builder.append("\nlengthModuleInformationSubstream: ");
		builder.append(lengthModuleInformationSubstream);
		builder.append("\nlengthSectionContributionSubstream: ");
		builder.append(lengthSectionContributionSubstream);
		builder.append("\nlengthSectionMap: ");
		builder.append(lengthSectionMap);
		builder.append("\nlengthFileInformation: ");
		builder.append(lengthFileInformation);
		writer.write(builder.toString());
	}

	@Override
	protected void dumpInternalSubstreams(Writer writer) throws IOException, CancelledException {
		writer.write("ModuleInformationList---------------------------------------\n");
		dumpModuleInformation(writer);
		writer.write("\nEnd ModuleInformationList-----------------------------------\n");
		writer.write("SectionContributionList-------------------------------------\n");
		dumpSectionContributions(writer);
		writer.write("\nEnd SectionContributionList---------------------------------\n");
		writer.write("SegmentMap--------------------------------------------------\n");
		dumpSegmentMap(writer);
		writer.write("\nEnd SegmentMap----------------------------------------------\n");
	}

}
