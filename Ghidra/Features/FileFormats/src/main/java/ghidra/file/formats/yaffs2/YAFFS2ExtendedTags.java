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
package ghidra.file.formats.yaffs2;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class YAFFS2ExtendedTags implements StructConverter {

	// extended tags (a footer really)
	private long sequenceNumber;
	private long objectId;
	private long chunkId;
	private long numberBytes;
	private long eccColParity;
	private long eccLineParity;
	private long eccLineParityPrime;

	public YAFFS2ExtendedTags(byte[] buffer) {

		// parse extended tags structure
		sequenceNumber = YAFFS2Utils.parseInteger(buffer, 0, 4);
		objectId = YAFFS2Utils.parseInteger(buffer, 4, 4);
		chunkId = YAFFS2Utils.parseInteger(buffer, 8, 4);
		numberBytes = YAFFS2Utils.parseInteger(buffer, 12, 4);
		eccColParity = YAFFS2Utils.parseInteger(buffer, 16, 4);
		eccLineParity = YAFFS2Utils.parseInteger(buffer, 20, 4);
		eccLineParityPrime = YAFFS2Utils.parseInteger(buffer, 24, 4);

	}

	public YAFFS2ExtendedTags() {
	}

	public long getObjectId() {
		return objectId;
	}

	public long getSequenceNumber() {
		return sequenceNumber;
	}

	public long getChunkId() {
		return chunkId;
	}

	public long getNumberBytes() {
		return numberBytes;
	}

	public long getEccColParity() {
		return eccColParity;
	}

	public long getEccLineParity() {
		return eccLineParity;
	}

	public long getEccLineParityPrime() {
		return eccLineParityPrime;
	}

	// extended tags structure for analyzer
	public DataType toDataType() throws DuplicateNameException, IOException {

		Structure structure = new StructureDataType("yaffs2Tags", 0);
		structure.add(DWORD, "sequenceNumber", null);
		structure.add(DWORD, "objectId", null);
		structure.add(DWORD, "chunkId", null);
		structure.add(DWORD, "numberBytes", null);
		structure.add(DWORD, "eccColParity", null);
		structure.add(DWORD, "eccLineParity", null);
		structure.add(DWORD, "eccLineParityPrime", null);
		structure.add(new ArrayDataType(BYTE, 36, BYTE.getLength()), "unused", null);
		return structure;

	}

}
