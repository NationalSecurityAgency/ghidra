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

import java.util.Arrays;

public class YAFFS2Entry {

	private long fileOffset;
	private YAFFS2Header header;
	private YAFFS2ExtendedTags extendedTags;

	/**
	 * in YAFFS2 speak, a record is called a "chunk"
	 * this class parses out a header chunk, reading the header and the footer in a record
	 */
	public YAFFS2Entry(byte[] buffer) {
		// header
		header = new YAFFS2Header(Arrays.copyOfRange(buffer, 0, YAFFS2Constants.HEADER_SIZE));

		// extended tags
		extendedTags =
			new YAFFS2ExtendedTags(Arrays.copyOfRange(buffer, YAFFS2Constants.DATA_BUFFER_SIZE,
				YAFFS2Constants.RECORD_SIZE));
	}

	public YAFFS2Entry() {
	}

	public long getObjectId() {
		return extendedTags.getObjectId();
	}

	public boolean isDirectory() {
		return header.isDirectory();
	}

	public short getChecksum() {
		return header.getChecksum();
	}

	public String getName() {
		return header.getName();
	}

	public long getYstMode() {
		return header.getYstMode();
	}

	public long getYstUId() {
		return header.getYstUId();
	}

	public long getYstGId() {
		return header.getYstGId();
	}

	public String getYstATime() {
		return header.getYstATime();
	}

	public String getYstMTime() {
		return header.getYstMTime();
	}

	public String getYstCTime() {
		return header.getYstCTime();
	}

	public long getSize() {
		return header.getSize();
	}

	public long getEquivId() {
		return header.getEquivId();
	}

	public String getAliasFileName() {
		return header.getAliasFileName();
	}

	public long getYstRDev() {
		return header.getYstRDev();
	}

	public long getWinCTime() {
		return header.getWinCTime();
	}

	public long getWinATime() {
		return header.getWinATime();
	}

	public long getWinMTime() {
		return header.getWinMTime();
	}

	public long getInbandObjId() {
		return header.getInbandObjId();
	}

	public long getInbandIsShrink() {
		return header.getInbandIsShrink();
	}

	public long getFileSizeHigh() {
		return header.getFileSizeHigh();
	}

	public long getShadowsObject() {
		return header.getShadowsObject();
	}

	public long getIsShrink() {
		return header.getIsShrink();
	}

	public long getSequenceNumber() {
		return extendedTags.getSequenceNumber();
	}

	public long getChunkId() {
		return extendedTags.getChunkId();
	}

	public long getNumberBytes() {
		return extendedTags.getNumberBytes();
	}

	public long getEccColParity() {
		return extendedTags.getEccColParity();
	}

	public long getEccLineParity() {
		return extendedTags.getEccLineParity();
	}

	public long getEccLineParityPrime() {
		return extendedTags.getEccLineParityPrime();
	}

	public long getParentObjectId() {
		return header.getParentObjectId();
	}

	public boolean isFile() {
		return header.isFile();
	}

	public void setFileOffset(Long foffset) {
		fileOffset = foffset;
	}

	public long getFileOffset() {
		return fileOffset;
	}

}
