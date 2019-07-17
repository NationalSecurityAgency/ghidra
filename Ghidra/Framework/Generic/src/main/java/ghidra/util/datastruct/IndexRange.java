/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.datastruct;

/**
 * Class for holding a begin and end index.
 */
public class IndexRange {
	private long start;
	private long end;
    /**
     * Constructor for IndexRange.
     * @param start the starting index of the range.
     * @param end the ending index of the range.
     */
    public IndexRange(long start, long end) {
        this.start = start;
        this.end = end;
    }
    /**
     * Returns the starting index of the range.
     * @return the starting index of the range.
     */
    public long getStart() {
    	return start;
    }
    /**
     * Returns the ending index of the range.
     * @return the ending index of the range.
     */
    public long getEnd() {
    	return end;
    }
    
	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
    public boolean equals(Object obj) {
		if (!(obj instanceof IndexRange))
			return false;
		IndexRange otherRange = (IndexRange)obj;
		return otherRange.start == start && otherRange.end == end;
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	@Override
    public int hashCode() {
		return (int)(start ^ (start >>> 32));
	}

}
