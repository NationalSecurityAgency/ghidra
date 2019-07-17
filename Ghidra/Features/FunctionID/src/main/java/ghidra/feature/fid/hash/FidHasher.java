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
package ghidra.feature.fid.hash;

import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * FidHasher is an interface with one method--hash.  It's used by the
 * FID system to hash a function for inclusion in a FID library, or for
 * searching the libraries for a match. 
 */
public interface FidHasher {
	/**
	 * Computes the hash for a given function.
	 * @param func the function to hash
	 * @return the FID hash quad (all 4 hashes at once) or null if there aren't enough code units
	 * @throws MemoryAccessException if the function body has an inaccessible code unit
	 */
	public FidHashQuad hash(Function func) throws MemoryAccessException;
}
