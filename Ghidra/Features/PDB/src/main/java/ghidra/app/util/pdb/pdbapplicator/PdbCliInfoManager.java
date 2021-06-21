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
package ghidra.app.util.pdb.pdbapplicator;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTable;
import ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTableRow;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;

/**
 * Manages CLI-Managed information, the bounds of which we do not yet know.
 */
public class PdbCliInfoManager {

	private CliStreamMetadata metadataStream;

	// TODO: May move these out from this class to a higher level.  Would mean passing in
	// the appropriate header to this constructor if we want to reuse that code.
	private boolean isDll = false;
	private boolean isAslr = false;

	/**
	 * Manager of CLI-related tables that we might need access to for PDB processing.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 */
	PdbCliInfoManager(PdbApplicator applicator) {
		Objects.requireNonNull(applicator, "applicator may not be null");
		metadataStream = getCliStreamMetadata(applicator);
	}

	boolean isDll() {
		return isDll;
	}

	boolean isAslr() {
		return isAslr;
	}

	CliAbstractTableRow getCliTableRow(int tableNum, int rowNum) throws PdbException {
		if (metadataStream == null) {
			throw new PdbException("CliStreamMetadata is null");
		}
		CliAbstractTable table = metadataStream.getTable(tableNum);
		if (table == null) {
			return null;
		}
		return table.getRow(rowNum);
	}

	private CliStreamMetadata getCliStreamMetadata(PdbApplicator applicator) {
		Program program = applicator.getProgram();
		if (program == null) {
			return null;
		}

		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		FileBytes fileBytes = allFileBytes.get(0); // Should be that of main imported file
		ByteProvider provider = new FileBytesProvider(fileBytes);
		PortableExecutable pe = null;
		try {
			GenericFactory factory = MessageLogContinuesFactory.create(applicator.getMessageLog());
			pe = PortableExecutable.createPortableExecutable(factory, provider, SectionLayout.FILE,
				true, true);
			NTHeader ntHeader = pe.getNTHeader();
			OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
			int characteristics = ntHeader.getFileHeader().getCharacteristics();
			isDll = (characteristics & FileHeader.IMAGE_FILE_DLL) == FileHeader.IMAGE_FILE_DLL;
			DataDirectory[] dataDirectory = optionalHeader.getDataDirectories();
			int optionalHeaderCharaceristics = optionalHeader.getDllCharacteristics();
			isAslr = (optionalHeaderCharaceristics &
				OptionalHeader.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) == OptionalHeader.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
			COMDescriptorDataDirectory comDir =
				(COMDescriptorDataDirectory) dataDirectory[OptionalHeader.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
			ImageCor20Header header = comDir.getHeader();
			if (header == null) {
				return null;
			}
			return header.getMetadata().getMetadataRoot().getMetadataStream();
		}
		catch (Exception e) {
			applicator.pdbLogAndInfoMessage(this, "Unable to retrieve CliStreamMetadata");
			return null;
		}
		finally {
			try {
				provider.close();
			}
			catch (IOException ioe) {
				applicator.pdbLogAndInfoMessage(this, "Problem closing ByteProvider");
			}
		}
	}
}
