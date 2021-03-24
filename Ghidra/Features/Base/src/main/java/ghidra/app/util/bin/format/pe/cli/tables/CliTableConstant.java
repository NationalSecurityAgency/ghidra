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
import ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliElementType;
import ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliTypeCodeDataType;
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigConstant;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexHasConstant;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Describes the Constant table. Each row represents a constant value for a Param, Field, or Property.
 */
public class CliTableConstant extends CliAbstractTable {
	public class CliConstantRow extends CliAbstractTableRow {
		public byte type;
		public byte reserved;
		public int parentIndex;
		public int valueIndex;

		public CliConstantRow(byte type, byte reserved, int parentIndex, int valueIndex) {
			super();
			this.type = type;
			this.reserved = reserved;
			this.parentIndex = parentIndex;
			this.valueIndex = valueIndex;
		}

		@Override
		public String getRepresentation() {
			String parentRep;
			try {
				parentRep = getRowRepresentationSafe(CliIndexHasConstant.getTableName(parentIndex),
					CliIndexHasConstant.getRowIndex(parentIndex));
			}
			catch (InvalidInputException e) {
				parentRep = Integer.toHexString(parentIndex);
			}
			return String.format("Type %d Parent %s Value %x", type, parentRep, valueIndex);
		}
	}

	public CliTableConstant(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliConstantRow row = new CliConstantRow(reader.readNextByte(), reader.readNextByte(),
				CliIndexHasConstant.readCodedIndex(reader, stream), readBlobIndex(reader));
			rows.add(row);
			blobs.add(row.valueIndex);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		for (CliAbstractTableRow row : rows) {
			CliConstantRow constantRow = (CliConstantRow) row;

			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor,
				log, ntHeader, metadataStream.getBlobStream(), constantRow.valueIndex);

			CliSigConstant constantSig =
				new CliSigConstant(metadataStream.getBlobStream().getBlob(constantRow.valueIndex),
					CliElementType.fromInt(constantRow.type));
			metadataStream.getBlobStream().updateBlob(constantSig, sigAddr, program);
		}
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "Constant Row", 0);
		rowDt.add(CliTypeCodeDataType.dataType, "Type", "if Class, indicates nullref");
		rowDt.add(BYTE, "Reserved", "should be 0");
		rowDt.add(CliIndexHasConstant.toDataType(metadataStream), "Parent",
			"index - coded HasConstant");
		rowDt.add(metadataStream.getBlobIndexDataType(), "Value", "index into Blob heap");
		return rowDt;
	}
}
