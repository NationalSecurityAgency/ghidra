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
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigField;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.flags.CliFlags.CliEnumFieldAttributes;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Describes the Field table. Each row represents a field in a TypeDef class. Fields are stored one after the other, grouped by class.
 * References to the Field table encode where the fields for a class start and end.
 */
public class CliTableField extends CliAbstractTable {
	public class CliFieldRow extends CliAbstractTableRow {
		public short flags;
		public int nameIndex;
		public int sigIndex;

		public static final int TYPEDEF_OWNER_INIT_VALUE = -1;
		public int typeDefOwnerIndex = TYPEDEF_OWNER_INIT_VALUE;

		public CliFieldRow(short flags, int nameIndex, int sigIndex) {
			super();
			this.flags = flags;
			this.nameIndex = nameIndex;
			this.sigIndex = sigIndex;
		}

		@Override
		public String getRepresentation() {
			String sigRep = Integer.toHexString(sigIndex);
			CliBlob sigBlob = metadataStream.getBlobStream().getBlob(sigIndex);
			try {
				CliSigField fieldSig;
				fieldSig = new CliSigField(sigBlob);
				sigRep = fieldSig.getShortRepresentation(metadataStream);
			}
			catch (IOException e) {
			}

			String ownerRep;
			if (typeDefOwnerIndex == TYPEDEF_OWNER_INIT_VALUE) {
				ownerRep = "";
			}
			else {
				ownerRep = getRowShortRepSafe(CliTypeTable.TypeDef, typeDefOwnerIndex) + "::";
			}

			return String.format("%s %s%s Flags %s", sigRep, ownerRep,
				metadataStream.getStringsStream().getString(nameIndex),
				CliEnumFieldAttributes.dataType.getName(flags & 0xffff));
		}
	}

	public CliTableField(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		CliTableTypeDef typeDefTable =
			(CliTableTypeDef) metadataStream.getTable(CliTypeTable.TypeDef);
		for (int i = 0; i < this.numRows; i++) {
			CliFieldRow row = new CliFieldRow(reader.readNextShort(), readStringIndex(reader),
				readBlobIndex(reader));
			rows.add(row);
			strings.add(row.nameIndex);

			// Figure out owner of this field
			row.typeDefOwnerIndex = typeDefTable.getOwnerOfFieldIndex(i);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		int fieldRowIndex = 0;
		for (CliAbstractTableRow row : rows) {
			CliFieldRow fieldRow = (CliFieldRow) row;
			fieldRowIndex++;

			// Create FieldSig object
			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor,
				log, ntHeader, metadataStream.getBlobStream(), fieldRow.sigIndex);

			CliSigField fieldSig =
				new CliSigField(metadataStream.getBlobStream().getBlob(fieldRow.sigIndex));

			if (!metadataStream.getBlobStream().updateBlob(fieldSig, sigAddr, program)) {
				Msg.warn(CliTableField.class,
					"Couldn't update FieldSig blob " +
						metadataStream.getStringsStream().getString(fieldRow.nameIndex) +
						" at Field table index " + fieldRowIndex);
			}
		}
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "Field Row", 0);
		rowDt.add(CliEnumFieldAttributes.dataType, "Flags", "see CorFieldAttr");
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		rowDt.add(metadataStream.getBlobIndexDataType(), "Signature", "index into Blob heap");
		return rowDt;
	}

}
