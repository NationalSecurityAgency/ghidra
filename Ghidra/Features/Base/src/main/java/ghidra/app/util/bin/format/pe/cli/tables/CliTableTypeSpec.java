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
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigTypeSpec;
import ghidra.app.util.bin.format.pe.cli.streams.CliAbstractStream;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Describes the TypeSpec table. Each row represents a specification for a TypeDef or TypeRef which is contained in the Blob stream.
 */
public class CliTableTypeSpec extends CliAbstractTable {
	public class CliTypeSpecRow extends CliAbstractTableRow {
		public int signatureIndex;

		public CliTypeSpecRow(int signatureIndex) {
			super();
			this.signatureIndex = signatureIndex;
		}

		@Override
		public String getRepresentation() {
			String sigRep = Integer.toHexString(signatureIndex);
			CliBlob blob = metadataStream.getBlobStream().getBlob(signatureIndex);
			try {
				CliSigTypeSpec sig = new CliSigTypeSpec(blob);
				sigRep = sig.getRepresentation();
			}
			catch (Exception e) {
			}
			return String.format("%s", sigRep);
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			String sigRep = Integer.toHexString(signatureIndex);
			CliBlob blob = stream.getBlobStream().getBlob(signatureIndex);
			try {
				CliSigTypeSpec sig = new CliSigTypeSpec(blob);
				sigRep = sig.getRepresentation(stream);
			}
			catch (Exception e) {
			}
			return String.format("%s", sigRep);
		}
	}

	public CliTableTypeSpec(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliTypeSpecRow row = new CliTypeSpecRow(readBlobIndex(reader));
			rows.add(row);
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		for (CliAbstractTableRow row : rows) {
			CliTypeSpecRow typeRow = (CliTypeSpecRow) row;
			CliBlob blob = metadataStream.getBlobStream().getBlob(typeRow.signatureIndex);

			// Get the address of the signature, create the TypeSpec object
			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor,
				log, ntHeader, metadataStream.getBlobStream(), typeRow.signatureIndex);

			CliSigTypeSpec typeSig = new CliSigTypeSpec(blob);
			metadataStream.getBlobStream().updateBlob(typeSig, sigAddr, program);
		}
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "TypeSpec Row", 0);
		rowDt.add(metadataStream.getBlobIndexDataType(), "Signature", "index into Blob heap");
		return rowDt;
	}

}
