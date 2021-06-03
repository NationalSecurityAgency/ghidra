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
package ghidra.app.util.bin.format.pdb2.pdbreader;

/**
 * Refer to PDB API.  This class models HasherV2.
 */
public class Hasher32V2 extends Hasher32 {

	/**
	 * Hashes (V2) {@link String}, using unsigned32BitMod, which the user should ensure
	 *  is <= 0xffffffff.  Returns an unsigned integer value (32-bit) returned as a long.
	 * @param string The input {@link String} to be hashed.
	 * @param unsigned32BitMod Modulus to be used for the hash.
	 * @return An unsigned integer hash value returned as a long.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	@Override
	public long hash(String string, long unsigned32BitMod) throws PdbException {
		byte[] bytes = string.getBytes();
		PdbByteReader reader = new PdbByteReader(bytes);
		int count = bytes.length;
		long hash = 0xb170a1bfL; // represents unsigned 32-bit.

		while (count >= 4) {
			count -= 4;
			hash += reader.parseUnsignedIntVal();
			hash += (hash << 10);
			hash ^= (hash >> 6);
		}
		// Hash remaining bytes.
		while (reader.hasMore()) {
			hash += reader.parseUnsignedByteVal();
			hash += (hash << 10);
			hash ^= (hash >> 6);
		}
		// Mask down to 32-bits.
		hash &= 0xffffffff;
		// Apply modulus.
		return hashUnsigned32Bit(hash) % unsigned32BitMod;
	}

	// From Numeric Recipes in C, second edition, pg 284
	private long hashUnsigned32Bit(long unsigned32BitVal) {
		return (unsigned32BitVal * 1664525L + 1013904223L) & 0xffffffff;
	}

}
