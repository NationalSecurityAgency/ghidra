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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.LoadCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a CS_SuperBlob structure
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h">osfmk/kern/cs_blobs.h</a> 
 */
public class CodeSignatureSuperBlob extends CodeSignatureGenericBlob {

	private int count;

	private List<CodeSignatureBlobIndex> indexList;
	private List<CodeSignatureGenericBlob> indexBlobs;

	/**
	 * Creates a new {@link CodeSignatureSuperBlob}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public CodeSignatureSuperBlob(BinaryReader reader) throws IOException {
		super(reader);
		count = reader.readNextInt();

		indexList = new ArrayList<>(count);
		for (int i = 0; i < count; i++) {
			indexList.add(new CodeSignatureBlobIndex(reader));
		}

		indexBlobs = new ArrayList<>(count);
		for (CodeSignatureBlobIndex blobIndex : indexList) {
			reader.setPointerIndex(base + blobIndex.getOffset());
			indexBlobs.add(CodeSignatureBlobParser.parse(reader));
		}
	}

	/**
	 * {@return the number of index entries}
	 */
	public int getCount() {
		return count;
	}

	/**
	 * {@return the index entries}
	 */
	public List<CodeSignatureBlobIndex> getIndexEntries() {
		return indexList;
	}

	/**
	 * {@return the index blobs}
	 */
	public List<CodeSignatureGenericBlob> getIndexBlobs() {
		return indexBlobs;
	}

	@Override
	public void markup(Program program, Address addr, MachHeader header, TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		try {
			for (int i = 0; i < count; i++) {
				CodeSignatureBlobIndex blobIndex = indexList.get(i);
				CodeSignatureGenericBlob blob = indexBlobs.get(i);
				Data d = DataUtilities.createData(program, addr.add(blobIndex.getOffset()),
					blob.toDataType(), -1, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				LoadCommand.setEndian(d, true);
				blob.markup(program, addr.add(blobIndex.getOffset()), header, monitor, log);
			}
		}
		catch (Exception e) {
			log.appendMsg(CodeSignatureSuperBlob.class.getSimpleName(),
				"Failed to markup CS_SuperBlob");
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("CS_SuperBlob", 0);
		struct.add(DWORD, "magic", "magic number");
		struct.add(DWORD, "length", "total length of SuperBlob");
		struct.add(DWORD, "count", "number of index entries following");
		if (!indexList.isEmpty()) {
			DataType dt = indexList.get(0).toDataType();
			struct.add(new ArrayDataType(dt, count, dt.getLength()), "index", "(count) entries");
		}
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}

}
