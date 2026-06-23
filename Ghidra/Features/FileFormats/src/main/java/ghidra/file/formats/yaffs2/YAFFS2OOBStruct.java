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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * Represents the data YAFFS2 puts in the OOB area of a page.  See the yaffs_guts.h for
 * yaffs_tags or yaffs_ext_tags, etc.
 * <p>
 * The layout of data in the OOB data can vary depending the version, size, and MTD-vs-yaffs
 * option used in mkyaffs.
 * <p>
 * We currently only care about the objectId, but a more fully-featured implementation might need
 * more information from this area.
 */
public class YAFFS2OOBStruct {

	/**
	 * Reads a yaffs2_ext_tag-formatted OOB data area.
	 * 
	 * @param br stream to read from
	 * @param oobSize size of the OOB data
	 * @return new {@link YAFFS2OOBStruct}, never null
	 * @throws IOException if error reading
	 */
	public static YAFFS2OOBStruct read(BinaryReader br, int oobSize) throws IOException {
		long start = br.getPointerIndex();
		YAFFS2OOBStruct result = new YAFFS2OOBStruct();
		result.sequenceNumber = br.readNextUnsignedInt();
		result.objectId = br.readNextUnsignedInt();
		br.setPointerIndex(start + oobSize);
		return result;
	}

	private long sequenceNumber;
	private long objectId;

	public YAFFS2OOBStruct() {
		// empty
	}

	public long getObjectId() {
		return objectId;
	}

	public long getSequenceNumber() {
		return sequenceNumber;
	}
}
