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
 * Refer to PDB API.  This class models LHashPbCb.
 */
public class Hasher32 extends Hasher {

	/**
	 * Hashes {@link String}, using unsigned32BitMod, which the user should ensure is <= 0xffffffff.
	 * Returns an unsigned integer value (32-bit) returned as a long.
	 * @param string The input {@link String} to be hashed.
	 * @param unsigned32BitMod Modulus to be used for the hash.
	 * @return An unsigned integer hash value returned as a long.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	@Override
	public long hash(String string, long unsigned32BitMod) throws PdbException {
		return hashString32(string, unsigned32BitMod);
	}

}
