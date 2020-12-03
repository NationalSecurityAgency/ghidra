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
import ghidra.app.util.bin.format.pe.cli.blobs.CliBlobMarshalSpec;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexHasFieldMarshall;
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
 * Describes the FieldMarshall table. Each row indicates how a Param or Field should be treated when calling from or to unmanaged code.
 */
public class CliTableFieldMarshall extends CliAbstractTable {
	public class CliFieldMarshallRow extends CliAbstractTableRow {
		public int parentIndex;
		public int nativeTypeIndex;

		public CliFieldMarshallRow(int parentIndex, int nativeTypeIndex) {
			super();
			this.parentIndex = parentIndex;
			this.nativeTypeIndex = nativeTypeIndex;
		}

		@Override
		public String getRepresentation() {
			String parentRep;
			try {
				parentRep =
					getRowRepresentationSafe(CliIndexHasFieldMarshall.getTableName(parentIndex),
						CliIndexHasFieldMarshall.getRowIndex(parentIndex));
			}
			catch (InvalidInputException e) {
				parentRep = Integer.toHexString(parentIndex);
			}
			String nativeTypeRep = Integer.toHexString(nativeTypeIndex); // TODO: Implement NativeType Blob
			return String.format("Parent %s Native Type %s", parentRep, nativeTypeRep);
		}
	}

	public CliTableFieldMarshall(BinaryReader reader, CliStreamMetadata stream,
			CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliFieldMarshallRow row = new CliFieldMarshallRow(
				CliIndexHasFieldMarshall.readCodedIndex(reader, stream), readBlobIndex(reader));
			rows.add(row);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt =
			new StructureDataType(new CategoryPath(PATH), "FieldMarshall Row", 0);
		rowDt.add(CliIndexHasFieldMarshall.toDataType(metadataStream), "Parent", null);
		rowDt.add(metadataStream.getBlobIndexDataType(), "NativeType", null);
		return rowDt;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		for (CliAbstractTableRow row : rows) {
			Integer nativeTypeIndex = ((CliFieldMarshallRow) row).nativeTypeIndex;
			Address addr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor, log,
				ntHeader, metadataStream.getBlobStream(), nativeTypeIndex);

			// Create MarshalSpec Blob object
			CliBlobMarshalSpec blob =
				new CliBlobMarshalSpec(metadataStream.getBlobStream().getBlob(nativeTypeIndex));
			metadataStream.getBlobStream().updateBlob(blob, addr, program);
		}
	}
}
