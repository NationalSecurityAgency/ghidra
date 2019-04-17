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

import java.util.LinkedList;

/**
 * Cross-reference container for different n-grams that share a particular hash
 *
 */
public class HashEntry {
	protected Hash hash;						// Hash being shared across n-grams
												// Note: the n-gram length is contained in the Hash object
	public LinkedList<InstructHash> instList;	// (Starting instruction of) n-grams with this hash
	public HashEntry(Hash h) {
		hash = h;
		instList = new LinkedList<InstructHash>();
	}

	/**
	 * @return true if any two InstructHash for this HashEntry share the same parent Block
	 */
	public boolean hasDuplicateBlocks() {
		boolean res = false;
		for(InstructHash curInstruct : instList) {
			if (curInstruct.block.isVisited) {		// If visited before
				res = true;							// Indicates multiple InstructHashes from one block
				break;
			}
			curInstruct.block.isVisited = true;		// Mark block as visited
		}
		for(InstructHash curInstruct : instList) {
			curInstruct.block.isVisited = false;	// Clear visited flag
		}
		return res;
	}
}
