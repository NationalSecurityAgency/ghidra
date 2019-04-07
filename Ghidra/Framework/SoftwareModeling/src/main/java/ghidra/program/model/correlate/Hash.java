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
package ghidra.program.model.correlate;

/**
 * This encodes the main hash value for an n-gram, and the number of Instructions hashed
 *
 */
public  class Hash implements Comparable<Hash> {
	// Initial accumulator values for the hash functions.  Should be non-zero for the CRC, but value doesn't matter otherwise
	public static final int SEED = 22222;
	public static final int ALTERNATE_SEED = 11111;	// Must be different from SEED

	protected int value;		// Actual hash value
	protected int size;		// Number of instructions involved in hash
	
	@Override
	public int compareTo(Hash o) {
		return Long.compare(value, o.value);
	}
	
	@Override
	public boolean equals(Object obj) {
		return value == ((Hash)obj).value;
	}
	
	@Override
	public int hashCode() {
		return value;
	}
	
	public Hash(int val,int sz) {
		value = val;
		size = sz;
	}
}
