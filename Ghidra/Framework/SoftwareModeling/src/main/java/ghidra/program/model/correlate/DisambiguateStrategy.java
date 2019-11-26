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

import java.util.ArrayList;

import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;

public interface DisambiguateStrategy {
	/**
	 * Generate (possibly multiple) hashes that can be used to disambiguate an n-gram and its block from other
	 * blocks with similar instructions.  Hashes are attached to the block's disambigHash list. 
	 * @param instHash the instruction hash
	 * @param matchSize the number of instructions to match
	 * @param store is the HashStore used to store the disambiguating hashes
	 * @return the list of disambiguating hashes
	 * @throws CancelledException 
	 * @throws MemoryAccessException 
	 */
	public ArrayList<Hash> calcHashes(InstructHash instHash, int matchSize, HashStore store) throws CancelledException, MemoryAccessException;
}
