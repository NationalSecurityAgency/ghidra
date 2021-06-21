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
package ghidra.app.util.bin.format.pe.cli.tables;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigAssembly;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumAssemblyFlags;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumAssemblyHashAlgorithm;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Describes the Assembly table. One-row table stores information about the current assembly.
 */
public class CliTableAssembly extends CliAbstractTable {

	public class CliAssemblyRow extends CliAbstractTableRow {
		public int hashAlg;
		public short majorVersion;
		public short minorVersion;
		public short buildNumber;
		public short revisionNumber;
		public int flags;
		public int publicKeyIndex;
		public int nameIndex;
		public int cultureIndex;

		public CliAssemblyRow(int hashAlg, short majorVersion, short minorVersion,
				short buildNumber, short revisionNumber, int flags, int publicKeyIndex,
				int nameIndex, int cultureIndex) {
			super();
			this.hashAlg = hashAlg;
			this.majorVersion = majorVersion;
			this.minorVersion = minorVersion;
			this.buildNumber = buildNumber;
			this.revisionNumber = revisionNumber;
			this.flags = flags;
			this.publicKeyIndex = publicKeyIndex;
			this.nameIndex = nameIndex;
			this.cultureIndex = cultureIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format(
				"%s v%d.%d build%d rev%d pubkey index %x culture index %x flags %s",
				metadataStream.getStringsStream().getString(nameIndex), majorVersion, minorVersion,
				buildNumber, revisionNumber, publicKeyIndex, cultureIndex,
				CliEnumAssemblyFlags.dataType.getName(flags & 0xffffffff));
		}
	}

	public CliTableAssembly(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		StructureDataType rowDt = (StructureDataType) this.toDataType();
		for (int i = 0; i < this.numRows; i++) {
			reader.setPointerIndex(this.readerOffset + rowDt.getLength() * i);
			CliAssemblyRow row = new CliAssemblyRow(reader.readNextInt(), reader.readNextShort(),
				reader.readNextShort(), reader.readNextShort(), reader.readNextShort(),
				reader.readNextInt(), readBlobIndex(reader), readStringIndex(reader),
				readStringIndex(reader));
			rows.add(row);
			blobs.add(row.publicKeyIndex);
			strings.add(row.nameIndex);
			strings.add(row.cultureIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public DataType getRowDataType() {
		return toDataType();
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		for (CliAbstractTableRow row : rows) {
			CliAssemblyRow assemblyRow = (CliAssemblyRow) row;

			if (assemblyRow.publicKeyIndex > 0) {
				Address sigAddr =
					CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor, log,
						ntHeader, metadataStream.getBlobStream(), assemblyRow.publicKeyIndex);

				CliSigAssembly assemblySig = new CliSigAssembly(
					metadataStream.getBlobStream().getBlob(assemblyRow.publicKeyIndex));
				metadataStream.getBlobStream().updateBlob(assemblySig, sigAddr, program);
			}
		}
	}

	@Override
	public DataType toDataType() {
		Structure table = new StructureDataType(new CategoryPath(PATH), "Assembly Table", 0);
		table.add(CliEnumAssemblyHashAlgorithm.dataType, "HashAlg", "Type of hash present");
		table.add(WORD, "MajorVersion", null);
		table.add(WORD, "MinorVersion", null);
		table.add(WORD, "BuildNumber", null);
		table.add(WORD, "RevisionNumber", null);
		table.add(CliEnumAssemblyFlags.dataType, "Flags", "Bitmask of type AssemblyFlags");
		table.add(metadataStream.getBlobIndexDataType(), "PublicKey", "index into Blob heap");
		table.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		table.add(metadataStream.getStringIndexDataType(), "Culture", "index into String heap");
		return table;
	}

}
