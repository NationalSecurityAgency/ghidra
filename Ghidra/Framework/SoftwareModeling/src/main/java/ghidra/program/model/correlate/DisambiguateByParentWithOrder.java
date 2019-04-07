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

import generic.hash.SimpleCRC32;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.util.exception.CancelledException;

/**
 * Attempt to disambiguate similar n-grams by looking at the parents, AND siblings, of blocks containing the n-grams.
 * This addresses switch constructions in particular, where code for individual cases look very similar but can be
 * distinguished by the ordering of the cases.
 *
 */
public class DisambiguateByParentWithOrder implements DisambiguateStrategy {

	@Override
	public ArrayList<Hash> calcHashes(InstructHash instHash, int matchSize, HashStore store) throws CancelledException {
		ArrayList<Hash> res = new ArrayList<Hash>();
		Block block = instHash.getBlock();
		CodeBlockReferenceIterator iter = block.origBlock.getSources(store.getMonitor());
		Address startAddr = block.origBlock.getMinAddress();
		while(iter.hasNext()) {			// Looking at each parent of -block- in turn
			CodeBlockReference ref = iter.next();
			Block srcBlock = store.getBlock(ref.getSourceAddress());
			if (srcBlock != null && srcBlock.getMatchHash() != 0) {
				CodeBlockReferenceIterator srcIter = srcBlock.origBlock.getDestinations(store.getMonitor());
				// Figure out the index of -block- within all blocks out of parent, sorted by address
				int totalcount = 0;
				int count = 0;
				while(srcIter.hasNext()) {
					Address addr = srcIter.next().getDestinationAddress();
					totalcount += 1;
					if (addr.compareTo(startAddr) < 0)	// If child is earlier than -block-
						count += 1;						//   increment index
				}
				if (totalcount <= 1) continue;			// If no siblings, this does no better than ParentStrategy
				count = SimpleCRC32.hashOneByte(srcBlock.getMatchHash(), count);	// Mix order index
				res.add(new Hash(count,1));											//   into disambiguation hash
			}
		}
		return res;
	}		
}
