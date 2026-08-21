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
package ghidra.app.util.bin.format.omf.omf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.omf.OmfException;
import ghidra.app.util.bin.format.omf.OmfUtils;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class OmfEnumeratedData extends OmfData {
	private long streamOffset;		// Position in stream where data starts
	private int streamLength;		// Number of bytes of data

	public OmfEnumeratedData(BinaryReader reader) throws IOException {
		super(reader);
	}

	@Override
	public void parseData() throws IOException, OmfException {
		long start = dataReader.getPointerIndex();
		segmentIndex = OmfUtils.readIndex(dataReader);
		dataOffset = OmfUtils.readInt2Or4(dataReader, hasBigFields());
		streamOffset = dataReader.getPointerIndex();
		streamLength = getRecordLength() - 1 - (int) (streamOffset - start);
	}

	@Override
	public int getLength() {
		return streamLength;
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

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return OmfUtils.toOmfRecordDataType(this, OmfRecordTypes.getName(recordType));
	}
}
