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

import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.util.exception.CancelledException;

/**
 * Attempt to disambiguate similar n-grams by looking at the children of blocks containing the n-grams
 *
 */
public class DisambiguateByChild implements DisambiguateStrategy {

	private static final int EXIT_BLOCK_HASH = 0x6a7b8c9d;		// Special hash for exit (childless) blocks

	@Override
	public ArrayList<Hash> calcHashes(InstructHash instHash, int matchSize, HashStore store) throws CancelledException {
		ArrayList<Hash> res = new ArrayList<Hash>();
		Block block = instHash.getBlock();
		CodeBlockReferenceIterator iter = block.origBlock.getDestinations(store.getMonitor());
		int count = 0;
		while(iter.hasNext()) {
			CodeBlockReference ref = iter.next();
			count += 1;
			Block destBlock = store.getBlock(ref.getDestinationAddress());
			if (destBlock != null && destBlock.getMatchHash() != 0) {	// For any child block previously matched
				res.add(new Hash(destBlock.getMatchHash(),1));			// Use its match hash as a disambiguator
			}
		}
		if (count == 0)
			res.add(new Hash(EXIT_BLOCK_HASH,1));						// Add hash indicating exit block
		return res;
	}		
}
