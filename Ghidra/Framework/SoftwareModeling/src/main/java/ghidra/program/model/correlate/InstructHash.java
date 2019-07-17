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

import java.util.Hashtable;

import ghidra.program.model.listing.Instruction;

/**
 * This class is the container for hashing information about a particular instruction, including all the
 * n-grams it is currently involved in within the HashStore.
 *
 */
public class InstructHash {
	protected boolean isMatched; // true if a 1-1 match has been found for this instruction
	protected int index;		// Index of this instruction within its block
	protected Block block;		// The containing basic block
	protected Instruction instruction;	// The underlying assembly instruction
	protected Hash[] nGrams;		// Different length hashes, within single basic block, over multiple instructions
	protected Hashtable<Hash,HashEntry> hashEntries;	// Cross-ref for n-grams/Instructions sharing the same hash
	
	/**
	 * Build an (unmatched) Instruction, associating it with its position in the basic block
	 * @param inst	is the underlying instruction
	 * @param bl is the basic-block
	 * @param ind is the index within the block
	 */
	public InstructHash(Instruction inst,Block bl,int ind) {
		isMatched = false;
		index = ind;
		block = bl;
		instruction = inst;
		nGrams = null;
		hashEntries = new Hashtable<Hash,HashEntry>();
	}

	/**
	 * @return the containing basic block
	 */
	public Block getBlock() {
		return block;
	}

	/**
	 * If the -length- instructions, starting with this, are all unmatched, return true;
	 * @param length is number of instructions to check
	 * @return true if all checked instructions are unmatched
	 */
	public boolean allUnknown(int length) {
		return block.allUnknown(index, length);
	}

	/**
	 * Clear out structures associated with the main sort
	 */
	protected void clearSort() {
		hashEntries = new Hashtable<Hash,HashEntry>();
	}

	/**
	 * Clear out the n-gram array to an uninitialized list
	 * @param sz is the size of the uninitialized list
	 */
	protected void clearNGrams(int sz) {
		nGrams = new Hash[sz];
	}
}
