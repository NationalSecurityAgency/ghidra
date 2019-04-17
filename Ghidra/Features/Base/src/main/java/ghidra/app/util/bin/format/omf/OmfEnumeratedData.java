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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class OmfEnumeratedData extends OmfRecord implements OmfData {
	private int segmentIndex;
	private long dataOffset;
	private long streamOffset;		// Position in stream where data starts
	private int streamLength;		// Number of bytes of data

	public OmfEnumeratedData(BinaryReader reader) throws IOException {
		readRecordHeader(reader);
		long start = reader.getPointerIndex();
		segmentIndex = OmfRecord.readIndex(reader);
		dataOffset = OmfRecord.readInt2Or4(reader, hasBigFields()) & 0xffffffffL;
		streamOffset = reader.getPointerIndex();
		streamLength = getRecordLength() - 1 - (int)(streamOffset - start);
		reader.setPointerIndex(streamOffset + streamLength); 	// Skip over the data when reading header
		readCheckSumByte(reader);
	}
	
	public int getSegmentIndex() {
		return segmentIndex;
	}

	@Override
	public long getDataOffset() {
		return dataOffset;
	}

	@Override
	public int getLength() {
		return streamLength;
	}
	
	@Override
	public int compareTo(OmfData o) {
		long otherOffset = o.getDataOffset();
		if (otherOffset == dataOffset) {
			return 0;
		}
		return (dataOffset < otherOffset) ? -1 : 1;
	}

	@Override
	public byte[] getByteArray(BinaryReader reader) throws IOException {
		reader.setPointerIndex(streamOffset);
		byte[] buffer = reader.readNextByteArray(streamLength);
		return buffer;
	}

	@Override
	public boolean isAllZeroes() {
		return false;
	}
}
