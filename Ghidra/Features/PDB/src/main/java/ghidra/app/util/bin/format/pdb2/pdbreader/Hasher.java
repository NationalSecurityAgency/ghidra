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
 * Refer to PDB API.  This class models HashPbCb.
 */
public class Hasher {

	/**
	 * Hashes {@link String}, using unsigned32BitMod, which the user should ensure is <= 0xffffffff.
	 * Returns an unsigned short value (16-bit) stored in a long.
	 * @param string The input {@link String} to be hashed.
	 * @param unsigned32BitMod Modulus to be used for the hash.
	 * @return An unsigned short hash value returned as a long.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public long hash(String string, long unsigned32BitMod) throws PdbException {
		return hashString32(string, unsigned32BitMod) & 0xffff;
	}

	/**
	 * Hashes {@link String}, using unsigned32BitMod, which the user should ensure is <= 0xffffffff.
	 * Returns an unsigned integer value (32-bit) returned as a long.
	 * @param string The input {@link String} to be hashed.
	 * @param unsigned32BitMod Modulus to be used for the hash.
	 * @return An unsigned integer hash value returned as a long.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected long hashString32(String string, long unsigned32BitMod) throws PdbException {
		byte[] bytes = string.getBytes();
		PdbByteReader reader = new PdbByteReader(bytes);
		int count = bytes.length;
		//int count = length >> 2; // Processing 32 bits at a time.
		long hash = 0; // represents unsigned int.

		while (count >= 4) {
			count -= 4;
			hash ^= reader.parseUnsignedIntVal();
		}
		if (bytes.length - reader.getIndex() >= 2) {
			hash ^= reader.parseUnsignedShortVal();
		}
		if (bytes.length - reader.getIndex() == 1) {
			hash ^= reader.parseUnsignedByteVal();
		}

		hash |= 0x20202020; // to-lower mask (not sure of effect after the above hashing)
		hash ^= (hash >> 11);
		// Mask down to 32-bits.
		hash &= 0xffffffff;
		// Apply modulus.
		return (hash ^ (hash >> 16)) % unsigned32BitMod;
	}

}
