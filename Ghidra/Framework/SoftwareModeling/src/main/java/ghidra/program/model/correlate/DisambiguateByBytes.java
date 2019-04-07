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

/**
 * Attempt to disambiguate similar n-grams by hashing over all the bytes in their constituent instructions.
 *
 */
public class DisambiguateByBytes implements DisambiguateStrategy {
	private AllBytesHashCalculator hashCalc = new AllBytesHashCalculator();

	@Override
	public ArrayList<Hash> calcHashes(InstructHash instHash, int matchSize, HashStore store) throws CancelledException, MemoryAccessException {
		ArrayList<Hash> res = new ArrayList<Hash>();
		Block block = instHash.getBlock();
		int val = block.hashGram(matchSize, instHash, hashCalc);		// Hash over n-gram's bytes
		res.add(new Hash(val,1));
		return res;
	}
}
