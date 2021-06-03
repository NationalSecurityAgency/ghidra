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
import ghidra.app.util.bin.format.pe.cli.blobs.CliBlob;
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigProperty;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumPropertyAttributes;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Describes the Property table. Each row describes a property. Indices into this table point to contiguous runs of properties
 * ending with the next index from the PropertyMap table or with the end of this table.
 */
public class CliTableProperty extends CliAbstractTable {
	private class CliPropertyRow extends CliAbstractTableRow {
		public short flags;
		public int nameIndex;
		public int sigIndex;

		public CliPropertyRow(short flags, int nameIndex, int sigIndex) {
			this.flags = flags;
			this.nameIndex = nameIndex;
			this.sigIndex = sigIndex;
		}

		@Override
		public String getRepresentation() {
			String sigRep = Integer.toHexString(sigIndex);
			CliBlob blob = metadataStream.getBlobStream().getBlob(sigIndex);
			try {
				CliSigProperty propertySig;
				propertySig = new CliSigProperty(blob);
				sigRep = propertySig.getShortRepresentation(metadataStream);
			}
			catch (IOException e) {
			}
			return String.format("Property %s Signature %s Flags %s",
				metadataStream.getStringsStream().getString(nameIndex), sigRep,
				CliEnumPropertyAttributes.dataType.getName(flags & 0xffff));
		}
	}

	public CliTableProperty(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliPropertyRow row = new CliPropertyRow(reader.readNextShort(), readStringIndex(reader),
				readBlobIndex(reader));
			rows.add(row);
			strings.add(row.nameIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "Property Row", 0);
		rowDt.add(CliEnumPropertyAttributes.dataType, "Flags",
			"Bitmask of type PropertyAttributes");
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", null);
		rowDt.add(metadataStream.getBlobIndexDataType(), "Type",
			"Blob index to the signature, not a TypeDef/TypeRef");
		return rowDt;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		for (CliAbstractTableRow row : rows) {
			CliPropertyRow property = (CliPropertyRow) row;
			CliBlob blob = metadataStream.getBlobStream().getBlob(property.sigIndex);
			Address addr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor, log,
				ntHeader, metadataStream.getBlobStream(), property.sigIndex);

			// Create PropertySig object
			CliSigProperty propSig = new CliSigProperty(blob);
			metadataStream.getBlobStream().updateBlob(propSig, addr, program);
		}
	}
}
