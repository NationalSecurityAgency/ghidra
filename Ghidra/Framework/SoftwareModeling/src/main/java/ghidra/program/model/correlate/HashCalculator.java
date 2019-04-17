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

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Interface for hashing across sequences of Instructions in different ways 
 *
 */
public interface HashCalculator {
	/**
	 * Calculate a (partial) hash across a single instruction
	 * @param startHash is initial hash value
	 * @param inst is the instruction to fold into the hash
	 * @return the final hash value
	 * @throws MemoryAccessException 
	 */
	public int calcHash(int startHash,Instruction inst) throws MemoryAccessException;
}
