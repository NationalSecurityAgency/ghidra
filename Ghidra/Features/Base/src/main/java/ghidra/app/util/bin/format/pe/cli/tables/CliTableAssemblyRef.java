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
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigAssemblyRef;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumAssemblyFlags;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Describes the AssemblyRef table. Each row is a reference to an external assembly.
 */
public class CliTableAssemblyRef extends CliAbstractTable {
	public class CliAssemblyRefRow extends CliAbstractTableRow {
		public short majorVersion;
		public short minorVersion;
		public short buildNumber;
		public short revisionNumber;
		public int flags;
		public int publicKeyOrTokenIndex;
		public int nameIndex;
		public int cultureIndex;
		public int hashValueIndex;

		public CliAssemblyRefRow(short majorVersion, short minorVersion, short buildNumber,
				short revisionNumber, int flags, int publicKeyOrTokenIndex, int nameIndex,
				int cultureIndex, int hashValueIndex) {
			super();
			this.majorVersion = majorVersion;
			this.minorVersion = minorVersion;
			this.buildNumber = buildNumber;
			this.revisionNumber = revisionNumber;
			this.flags = flags;
			this.publicKeyOrTokenIndex = publicKeyOrTokenIndex;
			this.nameIndex = nameIndex;
			this.cultureIndex = cultureIndex;
			this.hashValueIndex = hashValueIndex;
		}

		@Override
		public String getRepresentation() {
			return String.format(
				"AssemblyRef: %s v%d.%d build%d rev%d pubkey index %x culture index %x hash index %x flags %s",
				metadataStream.getStringsStream().getString(nameIndex), majorVersion, minorVersion,
				buildNumber, revisionNumber, publicKeyOrTokenIndex, cultureIndex, hashValueIndex,
				CliEnumAssemblyFlags.dataType.getName(flags & 0xffffffff));
		}

		@Override
		public String getShortRepresentation() {
			return String.format("%s v%d.%d build%d rev%d",
				metadataStream.getStringsStream().getString(nameIndex), majorVersion, minorVersion,
				buildNumber, revisionNumber);
		}
	}

	public CliTableAssemblyRef(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		StructureDataType rowDt = this.getRowDataType();
		for (int i = 0; i < this.numRows; i++) {
			reader.setPointerIndex(this.readerOffset + rowDt.getLength() * i);
			CliAssemblyRefRow row = new CliAssemblyRefRow(reader.readNextShort(),
				reader.readNextShort(), reader.readNextShort(), reader.readNextShort(),
				reader.readNextInt(), readBlobIndex(reader), readStringIndex(reader),
				readStringIndex(reader), readBlobIndex(reader));
			rows.add(row);
			blobs.add(row.publicKeyOrTokenIndex);
			strings.add(row.nameIndex);
			strings.add(row.cultureIndex);
			blobs.add(row.hashValueIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt =
			new StructureDataType(new CategoryPath(PATH), "AssemblyRef Row", 0);
		rowDt.add(WORD, "MajorVersion", null);
		rowDt.add(WORD, "MinorVersion", null);
		rowDt.add(WORD, "BuildNumber", null);
		rowDt.add(WORD, "RevisionNumber", null);
		rowDt.add(CliEnumAssemblyFlags.dataType, "Flags", "Bitmask of type AssemblyFlags"); // TODO: AssemblyFlags
		rowDt.add(metadataStream.getBlobIndexDataType(), "PublicKeyOrToken",
			"Public Key or token identifying the author of the assembly.");
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		rowDt.add(metadataStream.getStringIndexDataType(), "Culture", "index into String heap");
		rowDt.add(metadataStream.getBlobIndexDataType(), "HashValue", "index into Blob heap");
		return rowDt;
	}

	@Override
	public DataType toDataType() {
		DataType rowDt = getRowDataType();
		return new ArrayDataType(rowDt, this.numRows, rowDt.getLength());
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		for (CliAbstractTableRow row : rows) {
			CliAssemblyRefRow assemblyRefRow = (CliAssemblyRefRow) row;
			if (assemblyRefRow.hashValueIndex == 0) {
				continue;
			}

			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor,
				log, ntHeader, metadataStream.getBlobStream(), assemblyRefRow.hashValueIndex);

			CliSigAssemblyRef assemblyRefSig = new CliSigAssemblyRef(
				metadataStream.getBlobStream().getBlob(assemblyRefRow.hashValueIndex));
			metadataStream.getBlobStream().updateBlob(assemblyRefSig, sigAddr, program);
		}
	}
}
