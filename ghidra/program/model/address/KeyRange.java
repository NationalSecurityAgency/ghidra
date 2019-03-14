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
package ghidra.program.model.address;

/**
 * Class for holding a range of database keys (long values)
 */
public class KeyRange {
	public long minKey;
	public long maxKey;
	
	/**
	 * Constructs a new key range.  Keys must be ordered and unsigned.
	 * @param minKey the min key (inclusive)
	 * @param maxKey the max key (inclusive)
	 */
	public KeyRange(long minKey, long maxKey) {
		this.minKey = minKey;
		this.maxKey = maxKey;
	}
	
	/**
	 * Tests if the given key is in the range.
	 * @param key the key to test
	 * @return true if the key is in the range, false otherwise
	 */
	public boolean contains(long key) {
		return key>=minKey && key<=maxKey;
	}

	/**
	 * Return the number of keys contained within range.
	 * @return number of keys contained within range
	 */
	public long length() {
		return maxKey - minKey + 1;
	}
}
