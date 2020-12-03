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
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigMethodSpec;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexMethodDefOrRef;
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
 * Describes the MethodSpec table. Each row is a unique instantiation of a generic method.
 */
public class CliTableMethodSpec extends CliAbstractTable {
	public class CliMethodSpecRow extends CliAbstractTableRow {
		public int methodIndex;
		public int instantiationIndex;

		public CliMethodSpecRow(int methodIndex, int instantiationIndex) {
			super();
			this.methodIndex = methodIndex;
			this.instantiationIndex = instantiationIndex;
		}

		@Override
		public String getRepresentation() {
			String methodRep;
			try {
				methodRep =
					getRowRepresentationSafe(CliIndexMethodDefOrRef.getTableName(methodIndex),
						CliIndexMethodDefOrRef.getRowIndex(methodIndex));
			}
			catch (InvalidInputException e) {
				methodRep = Integer.toHexString(methodIndex);
			}
			String instantiationRep = Integer.toHexString(instantiationIndex);
			CliBlob blob = metadataStream.getBlobStream().getBlob(instantiationIndex);
			try {
				CliSigMethodSpec sig = new CliSigMethodSpec(blob);
				instantiationRep = sig.getRepresentation();
			}
			catch (Exception e) {
			}
			return String.format("Method %s Instantiation %s", methodRep, instantiationRep);
		}
	}

	public CliTableMethodSpec(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliMethodSpecRow row = new CliMethodSpecRow(
				CliIndexMethodDefOrRef.readCodedIndex(reader, stream), readBlobIndex(reader));
			rows.add(row);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		for (CliAbstractTableRow row : rows) {
			CliMethodSpecRow methodRow = (CliMethodSpecRow) row;
			CliBlob blob = metadataStream.getBlobStream().getBlob(methodRow.instantiationIndex);

			// Create the MethodSpecSig
			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor,
				log, ntHeader, metadataStream.getBlobStream(), methodRow.instantiationIndex);

			CliSigMethodSpec methodSig = new CliSigMethodSpec(blob);
			metadataStream.getBlobStream().updateBlob(methodSig, sigAddr, program);
		}
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt =
			new StructureDataType(new CategoryPath(PATH), "MethodSpec Row", 0);
		rowDt.add(CliIndexMethodDefOrRef.toDataType(metadataStream), "Method",
			"MethodDefOrRef coded index");
		rowDt.add(metadataStream.getBlobIndexDataType(), "Instantiation",
			"index into Blob heap, signature of this instantiation");
		return rowDt;
	}

}
