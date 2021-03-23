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
import ghidra.app.util.bin.format.pe.cli.blobs.*;
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
 * Describes the StandAloneSig table. Each row represents a signature that isn't referenced by any other Table.
 */
public class CliTableStandAloneSig extends CliAbstractTable {
	public class CliStandAloneSigRow extends CliAbstractTableRow {
		public int signatureIndex;

		public CliStandAloneSigRow(int signatureIndex) {
			this.signatureIndex = signatureIndex;
		}

		@Override
		public String getRepresentation() {
			String sigRep = Integer.toHexString(signatureIndex);
			CliBlob sigBlob = metadataStream.getBlobStream().getBlob(signatureIndex);
			try {
				CliAbstractSig sig;
				if (CliSigLocalVar.isLocalVarSig(sigBlob)) {
					sig = new CliSigLocalVar(sigBlob);
				}
				else if (CliSigField.isFieldSig(sigBlob)) {
					// UNDOCUMENTED FEATURE ALERT! Contrary to ISO standards Microsoft compilers
					// will sometimes put FieldSig references in this table.
					sig = new CliSigField(sigBlob);
				}
				else {
					sig = new CliSigStandAloneMethod(sigBlob);
				}
				sigRep = sig.getRepresentation();
			}
			catch (Exception e) {
			}
			return String.format("%s", sigRep);
		}
	}

	public CliTableStandAloneSig(BinaryReader reader, CliStreamMetadata stream,
			CliTypeTable tableId) throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			rows.add(new CliStandAloneSigRow(readBlobIndex(reader)));
		}
		reader.setPointerIndex(this.readerOffset);
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt =
			new StructureDataType(new CategoryPath(PATH), "StandAloneSig Row", 0);
		rowDt.add(metadataStream.getBlobIndexDataType(), "Signature", null);
		return rowDt;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		for (CliAbstractTableRow row : rows) {
			Integer sigIndex = ((CliStandAloneSigRow) row).signatureIndex;

			CliBlob blob =
				metadataStream.getBlobStream().getBlob(((CliStandAloneSigRow) row).signatureIndex);
			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor,
				log, ntHeader, metadataStream.getBlobStream(), sigIndex);

			// Create one of several *Sig objects
			if (CliSigLocalVar.isLocalVarSig(blob)) {
				CliSigLocalVar localSig = new CliSigLocalVar(blob);
				metadataStream.getBlobStream().updateBlob(localSig, sigAddr, program);
			}
			else if (CliSigField.isFieldSig(blob)) {
				// UNDOCUMENTED FEATURE ALERT! Contrary to ISO standards Microsoft compilers
				// will sometimes put FieldSig references in this table.
				CliSigField fieldSig = new CliSigField(blob);
				metadataStream.getBlobStream().updateBlob(fieldSig, sigAddr, program);
			}
			else {
				CliSigStandAloneMethod standAloneSig = new CliSigStandAloneMethod(blob);
				metadataStream.getBlobStream().updateBlob(standAloneSig, sigAddr, program);
			}
		}
	}
}
