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
 * Attempt to disambiguate similar n-grams by looking at the parents of blocks containing the n-grams
 *
 */
public class DisambiguateByParent implements DisambiguateStrategy {

	private static final int ENTRY_BLOCK_HASH = 0x9a8b7c6d;		// Special hash for entry (parentless) blocks

	@Override
	public ArrayList<Hash> calcHashes(InstructHash instHash, int matchSize, HashStore store) throws CancelledException {
		ArrayList<Hash> res = new ArrayList<Hash>();
		Block block = instHash.getBlock();
		CodeBlockReferenceIterator iter = block.origBlock.getSources(store.getMonitor());
		int count = 0;
		while(iter.hasNext()) {
			CodeBlockReference ref = iter.next();
			count += 1;
			Block srcBlock = store.getBlock(ref.getSourceAddress());
			if (srcBlock != null && srcBlock.getMatchHash() != 0) {	// For every parent previously matched
				res.add(new Hash(srcBlock.getMatchHash(),1));		// Use its match hash as a disambiguator
			}
		}
		if (count == 0)	
			res.add(new Hash(ENTRY_BLOCK_HASH,1));					// Add hash indicating entry block
		return res;
	}		
}
