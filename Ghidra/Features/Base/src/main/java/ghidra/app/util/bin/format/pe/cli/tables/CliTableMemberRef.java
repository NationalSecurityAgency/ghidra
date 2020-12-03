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
import ghidra.app.util.bin.format.pe.cli.tables.indexes.CliIndexMemberRefParent;
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
 * Describes the MemberRef/MethodRef table. Each row represents an imported method.
 */
public class CliTableMemberRef extends CliAbstractTable {
	public class CliMemberRefRow extends CliAbstractTableRow {
		public int classIndex;
		public int nameIndex;
		public int signatureIndex;

		public CliMemberRefRow(int classIndex, int nameIndex, int signatureIndex) {
			this.classIndex = classIndex;
			this.nameIndex = nameIndex;
			this.signatureIndex = signatureIndex;
		}

		@Override
		public String getRepresentation() {
			String classRep;
			try {
				classRep =
					getRowRepresentationSafe(CliIndexMemberRefParent.getTableName(classIndex),
						CliIndexMemberRefParent.getRowIndex(classIndex));
			}
			catch (InvalidInputException e) {
				classRep = Integer.toHexString(classIndex);
			}
			String sigRep = Integer.toHexString(signatureIndex);
			CliBlob sigBlob = metadataStream.getBlobStream().getBlob(signatureIndex);
			try {
				if (CliSigField.isFieldSig(sigBlob)) {
					CliSigField fieldSig = new CliSigField(sigBlob);
					sigRep = fieldSig.getRepresentation();
				}
				else {
					CliSigMethodRef methodSig = new CliSigMethodRef(sigBlob);
					sigRep = methodSig.getRepresentation();
				}
			}
			catch (IOException e) {
			}
			return String.format("Class(%s) Member(%s) Signature %s", classRep,
				metadataStream.getStringsStream().getString(nameIndex), sigRep);
		}

		@Override
		public String getRepresentation(CliStreamMetadata stream) {
			String classRep;
			try {
				classRep = getRowShortRepSafe(CliIndexMemberRefParent.getTableName(classIndex),
					CliIndexMemberRefParent.getRowIndex(classIndex));
			}
			catch (InvalidInputException e) {
				classRep = Integer.toHexString(classIndex);
			}
			String sigRep = Integer.toHexString(signatureIndex);
			CliBlob sigBlob = stream.getBlobStream().getBlob(signatureIndex);
			try {
				if (CliSigField.isFieldSig(sigBlob)) {
					CliSigField fieldSig = new CliSigField(sigBlob);
					sigRep = fieldSig.getShortRepresentation(stream);
				}
				else {
					CliSigMethodRef methodSig = new CliSigMethodRef(sigBlob);
					sigRep = methodSig.getRepresentation();
				}
			}
			catch (IOException e) {
			}
			return String.format("%s.%s %s", classRep,
				stream.getStringsStream().getString(nameIndex), sigRep);
		}
	}

	public CliTableMemberRef(BinaryReader reader, CliStreamMetadata stream, CliTypeTable tableId)
			throws IOException {
		super(reader, stream, tableId);
		for (int i = 0; i < this.numRows; i++) {
			CliMemberRefRow row =
				new CliMemberRefRow(CliIndexMemberRefParent.readCodedIndex(reader, stream),
					readStringIndex(reader), readBlobIndex(reader));
			rows.add(row);
			strings.add(row.nameIndex);
		}
		reader.setPointerIndex(this.readerOffset);

	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader)
			throws DuplicateNameException, CodeUnitInsertionException, IOException {
		for (CliAbstractTableRow row : rows) {
			CliMemberRefRow memberRow = (CliMemberRefRow) row;

			// Get the address and create one of several kinds of *Sig objects
			Address sigAddr = CliAbstractStream.getStreamMarkupAddress(program, isBinary, monitor,
				log, ntHeader, metadataStream.getBlobStream(), memberRow.signatureIndex);

			CliBlob sigBlob = metadataStream.getBlobStream().getBlob(memberRow.signatureIndex);
			if (CliSigField.isFieldSig(sigBlob)) {
				CliSigField fieldSig = new CliSigField(sigBlob);
				metadataStream.getBlobStream().updateBlob(fieldSig, sigAddr, program);
			}
			else {
				CliSigMethodRef methodSig = new CliSigMethodRef(sigBlob);
				metadataStream.getBlobStream().updateBlob(methodSig, sigAddr, program);
			}
		}
	}

	@Override
	public StructureDataType getRowDataType() {
		StructureDataType rowDt = new StructureDataType(new CategoryPath(PATH), "MemberRef Row", 0);
		rowDt.add(CliIndexMemberRefParent.toDataType(metadataStream), "Class",
			"index-MemberRefParent coded");
		rowDt.add(metadataStream.getStringIndexDataType(), "Name", "index into String heap");
		rowDt.add(metadataStream.getBlobIndexDataType(), "Signature", "index into Blob heap");
		return rowDt;
	}

}
