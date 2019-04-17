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

import generic.hash.SimpleCRC32;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Hash function hashing only the mnemonic of an individual Instruction
 *
 */
public class MnemonicHashCalculator implements HashCalculator {
	@Override
	public int calcHash(int startHash, Instruction inst) throws MemoryAccessException {
		String mnemonic = inst.getMnemonicString();
		for(int i=0;i<mnemonic.length();++i)
			startHash = SimpleCRC32.hashOneByte(startHash, mnemonic.charAt(i));
		return startHash;
	}
}
