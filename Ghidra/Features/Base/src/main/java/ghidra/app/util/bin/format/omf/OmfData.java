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

/**
 * Object representing data loaded directly into the final image.
 */
public abstract class OmfData extends OmfRecord implements Comparable<OmfData> {
	protected int segmentIndex;
	protected long dataOffset;

	/**
	 * @return get the segments index for this datablock
	 */
	public int getSegmentIndex() {
		return segmentIndex;
	}

	/**
	 * @return the starting offset, within the loaded image, of this data
	 */
	public long getDataOffset() {
		return dataOffset;
	}

	/**
	 * Compare datablocks by data offset
	 * @return a value less than 0 for lower address, 0 for same address, or greater than 0 for
	 *   higher address
	 */
	@Override
	public int compareTo(OmfData o) {
		return Long.compare(dataOffset, o.dataOffset);
	}

	/**
	 * @return the length of this data in bytes
	 */
	public abstract int getLength();

	/**
	 * Create a byte array holding the data represented by this object. The length
	 * of the byte array should exactly match the value returned by getLength()
	 * @param reader is for pulling bytes directly from the binary image
	 * @return allocated and filled byte array
	 * @throws IOException for problems accessing data through the reader
	 */
	public abstract byte[] getByteArray(BinaryReader reader) throws IOException;

	/**
	 * @return true if this is a block entirely of zeroes
	 */
	public abstract boolean isAllZeroes();
}
