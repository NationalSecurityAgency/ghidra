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
package ghidra.app.util.bin.format.macho.commands.codesignature;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a CS_BlobIndex structure
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h">osfmk/kern/cs_blobs.h</a> 
 */
@SuppressWarnings("unused")
public class CodeSignatureCodeDirectory extends CodeSignatureGenericBlob {

	private int version;
	private int flags;
	private int hashOffset;
	private int identOffset;
	private int nSpecialSlots;
	private int nCodeSlots;
	private int codeLimit;
	private int hashSize;
	private int hashType;
	private int platform;
	private int pageSize;
	private int spare2;
	private int scatterOffset;
	private int teamOffset;
	private int spare3;
	private long codeLimit64;
	private long execSegBase;
	private long execSegLimit;
	private long execSegFlags;
	private int runtime;
	private int preEncryptOffset;
	private int linkageHashType;
	private int linkageHashApplicationType;
	private int linkageApplicationSubType;
	private int linkageOffset;
	private int linkageSize;

	/**
	 * Creates a new {@link CodeSignatureCodeDirectory}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public CodeSignatureCodeDirectory(BinaryReader reader) throws IOException {
		super(reader);

		version = reader.readNextInt();
		flags = reader.readNextInt();
		hashOffset = reader.readNextInt();
		identOffset = reader.readNextInt();
		nSpecialSlots = reader.readNextInt();
		nCodeSlots = reader.readNextInt();
		codeLimit = reader.readNextInt();
		hashSize = reader.readNextUnsignedByte();
		hashType = reader.readNextUnsignedByte();
		platform = reader.readNextUnsignedByte();
		pageSize = reader.readNextUnsignedByte();
		spare2 = reader.readNextInt();
		if (version >= 0x20100) {
			scatterOffset = reader.readNextInt();
		}
		if (version >= 0x20200) {
			teamOffset = reader.readNextInt();
		}
		if (version >= 0x20300) {
			spare3 = reader.readNextInt();
			codeLimit64 = reader.readNextLong();
		}
		if (version >= 0x20400) {
			execSegBase = reader.readNextLong();
			execSegLimit = reader.readNextLong();
			execSegFlags = reader.readNextLong();
		}
		if (version >= 0x20500) {
			runtime = reader.readNextInt();
			preEncryptOffset = reader.readNextInt();
		}
		if (version >= 0x20600) {
			linkageHashType = reader.readNextUnsignedByte();
			linkageHashApplicationType = reader.readNextUnsignedByte();
			linkageApplicationSubType = reader.readNextUnsignedShort();
			linkageOffset = reader.readNextInt();
			linkageSize = reader.readNextInt();
		}
	}

	@Override
	public void markup(Program program, Address addr, MachHeader header, TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		try {
			if (identOffset != 0) {
				Address identAddr = addr.add(identOffset);
				DataUtilities.createData(program, identAddr, STRING, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				program.getListing()
						.setComment(identAddr, CodeUnit.PRE_COMMENT, "CS_CodeDirectory identifer");
			}
			if (teamOffset != 0) {
				Address teamAddr = addr.add(teamOffset);
				DataUtilities.createData(program, teamAddr, STRING, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				program.getListing()
						.setComment(teamAddr, CodeUnit.PRE_COMMENT,
							"CS_CodeDirectory team identifier");
			}
			if (hashOffset != 0 && hashSize != 0) {
				Address hashAddr = addr.add(hashOffset);
				DataType hashArrayDt = new ArrayDataType(BYTE, hashSize, 1);
				DataType hasheArrayArrayDt = new ArrayDataType(hashArrayDt, nCodeSlots, 1);
				DataUtilities.createData(program, hashAddr, hasheArrayArrayDt, -1,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				program.getListing()
						.setComment(hashAddr, CodeUnit.PRE_COMMENT, "CS_CodeDirectory hashes");
			}
		}
		catch (Exception e) {
			log.appendMsg(CodeSignatureCodeDirectory.class.getSimpleName(),
				"Failed to markup CS_CodeDirectory");
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("CS_CodeDirectory", 0);
		struct.add(DWORD, "magic", "magic number (CSMAGIC_CODEDIRECTORY)");
		struct.add(DWORD, "length", "total length of CodeDirectory blob");
		struct.add(DWORD, "version", "compatibility version");
		struct.add(DWORD, "flags", "setup and mode flags");
		struct.add(DWORD, "hashOffset", "offset of hash slot element at index zero");
		struct.add(DWORD, "identOffset", "offset of identifier string");
		struct.add(DWORD, "nSpecialSlots", "number of special hash slots");
		struct.add(DWORD, "nCodeSlots", "number of ordinary (code) hash slots");
		struct.add(DWORD, "codeLimit", "limit to main image signature range");
		struct.add(BYTE, "hashSize", "size of each hash in bytes");
		struct.add(BYTE, "hashType", "type of hash (cdHashType* constants)");
		struct.add(BYTE, "platform", "platform identifier; zero if not platform binary");
		struct.add(BYTE, "pageSize", "log2(page size in bytes); 0 => infinite");
		struct.add(DWORD, "spare2", "unused (must be zero)");
		if (version >= 0x20100) {
			struct.add(DWORD, "scatterOffset", "offset of optional scatter vector");
		}
		if (version >= 0x20200) {
			struct.add(DWORD, "teamOffset", "offset of optional team identifier");
		}
		if (version >= 0x20300) {
			struct.add(DWORD, "spare3", "unused (must be zero)");
			struct.add(QWORD, "codeLimit64", "limit to main image signature range, 64 bits");
		}
		if (version >= 0x20400) {
			struct.add(QWORD, "execSegBase", "offset of executable segment");
			struct.add(QWORD, "execSegLimit", "limit of executable segment");
			struct.add(QWORD, "execSegFlags", "executable segment flags");
		}
		if (version >= 0x20500) {
			struct.add(DWORD, "runtime", "");
			struct.add(DWORD, "preEncryptOffset", "");
		}
		if (version >= 0x20600) {
			struct.add(BYTE, "linkageHashType", "");
			struct.add(BYTE, "linkageHashApplicationType", "");
			struct.add(WORD, "linkageApplicationSubType", "");
			struct.add(DWORD, "linkageOffset", "");
			struct.add(DWORD, "linkageSize", "");
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

}
