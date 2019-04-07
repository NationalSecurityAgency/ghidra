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
package db.buffers;

/**
 * <code>ChangeMap</code> facilitates the decoding of change-data 
 * to determine if a specific buffer was modified by the 
 * corresponding buffer file version.
 * @see ChangeMapFile
 */
public class ChangeMap {

	private final byte[] mapData;
	private final int maxIndex;

	/**
	 * Constructor.
	 * @param mapData change map data
	 */
	public ChangeMap(byte[] mapData) {
		this.mapData = mapData;
		this.maxIndex = (mapData.length * 8) - 1;
	}
	
	/**
	 * Get the underlying change map data as a byte array
	 * @return change map data
	 */
	public byte[] getData() {
		return mapData;
	}

	/**
	 * Add the specified map data to this map within the size constraints
	 * of this map.
	 * @param otherMapData
	 */
	void addChangeMapData(byte[] otherMapData) {
		int limit = mapData.length;
		if (otherMapData.length < limit) {
			limit = otherMapData.length;
		}
		for (int byteOffset = 0; byteOffset < limit; byteOffset++) {
			mapData[byteOffset] |= otherMapData[byteOffset];
		}
	}

	/**
	 * Flag all indexes as changed within this change map.  Index values outside
	 * the size constraints of this map will be ignored.
	 * @param indexes list of indexes to mark as changed
	 */
	void setChangedIndexes(int[] indexes) {
		for (int index : indexes) {
			if (index > maxIndex) {
				continue;
			}
			int byteOffset = index / 8;
			int bitMask = 1 << (index % 8);
			mapData[byteOffset] |= bitMask;
		}
	}

	/**
	 * Flag all indexes as unchanged within this change map.  Index values outside
	 * the size constraints of this map will be ignored.
	 * @param indexes list of indexes to mark as unchanged
	 */
	void setUnchangedIndexes(int[] indexes) {
		for (int index : indexes) {
			if (index > maxIndex) {
				continue;
			}
			int byteOffset = index / 8;
			int bitMask = ~(1 << (index % 8));
			mapData[byteOffset] &= bitMask;
		}
	}

	/**
	 * Returns true if the change map data indicates that the 
	 * specified buffer has been modified.
	 * @param index buffer index
	 */
	public boolean hasChanged(int index) {
		if (mapData == null || index > maxIndex) {
			return true; // must be a new buffer index
		}
		int byteOffset = index / 8;
		int bitMask = 1 << (index % 8);
		return (mapData[byteOffset] & bitMask) != 0;
	}

	/**
	 * Returns true if the specified index is within the bounds of this map.
	 */
	public boolean containsIndex(int index) {
		return index <= maxIndex;
	}
}
