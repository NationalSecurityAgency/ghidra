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
import ghidra.app.util.bin.StructConverter;
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
 * Represents a CS_GenericBlob structure
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h">osfmk/kern/cs_blobs.h</a> 
 */
public class CodeSignatureGenericBlob implements StructConverter {

	protected int magic;
	protected int length;

	protected long base;

	/**
	 * Creates a new {@link CodeSignatureGenericBlob}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public CodeSignatureGenericBlob(BinaryReader reader) throws IOException {
		base = reader.getPointerIndex();
		magic = reader.readNextInt();
		length = reader.readNextInt();
	}

	/**
	 * {@return the magic}
	 */
	public int getMagic() {
		return magic;
	}

	/**
	 * {@return the length}
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Marks up this {@link CodeSignatureGenericBlob} data with data structures and comments
	 * 
	 * @param program The {@link Program} to mark up
	 * @param address The {@link Address} of the blob
	 * @param header The Mach-O header
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void markup(Program program, Address address, MachHeader header, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		if (length - 8 == 0) {
			return;
		}
		try {
			DataType dt = new ArrayDataType(BYTE, length - 8, 1);
			Address hashAddr = address.add(toDataType().getLength());
			DataUtilities.createData(program, hashAddr, dt, -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			program.getListing().setComment(hashAddr, CodeUnit.PRE_COMMENT, "CS_GenericBlob hash");
		}
		catch (Exception e) {
			log.appendMsg(CodeSignatureGenericBlob.class.getSimpleName(),
				"Failed to markup CS_GenericBlob");
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("CS_GenericBlob", 0);
		struct.add(DWORD, "magic", "magic number");
		struct.add(DWORD, "length", "total length of blob");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
