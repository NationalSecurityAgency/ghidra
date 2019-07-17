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

import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * This class holds basic-block information for matching algorithms. It is used as a node to traverse the
 * control-flow graph. It serves as a container for hashing information associated with Instructions in the
 * block.  It holds disambiguating hashes (calculated primarily from basic-block parent/child relationships)
 * to help separate identical or near identical sequences of Instructions within one function.
 *
 */
public class Block {		// Basic block within the function
	protected boolean isMatched;	// true if a 1-to-1 match for this block has been found
	protected boolean isVisited;	// true if algorithm has visited this block before
	protected CodeBlock origBlock;	// The underlying basic-block being described
	private int matchHash;		// If block has been matched, this value is fed to hashes to deconflict further matches
	protected InstructHash[] instList;	// List of Instructions (and corresponding hashing info) for this block
	
	public Block(CodeBlock codeBlock) {
		isMatched = false;
		isVisited = false;
		origBlock = codeBlock;
		matchHash= 0;				// Should be zero for an unknown block
		instList = null;
	}

	/**
	 * Clear out structures associated with main sort
	 */
	protected void clearSort() {
		for (InstructHash element : instList)
			element.clearSort();
	}

	/**
	 * Set up block match deconfliction value matchHash. This is fed into the n-gram hashes for Instructions
	 * contained by this block to uniquely associate the n-grams with this block (and the matching block on
	 * the other side)
	 * @param index is the 1-up index used to uniquely label this block
	 */
	protected void setMatched(int index) {
		isMatched = true;			// Mark that this block has been matched
		// Calculate value to feed into hashes
		// Achieve better bit diversity within the 32-bit value using expanding (not stabilizing) transformations.
		// Both addition,and multiplication by relatively prime values, are still invertible module 2^32, so
		// no information contained in -index- is lost. Otherwise the exact values don't matter much.
		matchHash = index * 7919;
		matchHash += 511;
		matchHash *= 4691;
	}

	/**
	 * @return the main deconfliction hash feed
	 */
	public int getMatchHash() {
		return matchHash;
	}

	/**
	 * If the indicated n-gram, within this block, consists of unmatched instructions
	 * @param startindex is the index of the first Instruction in the n-gram
	 * @param length is the number of instructions in the n-gram
	 * @return true if all Instructions in the n-gram are not matched, false otherwise.
	 */
	protected boolean allUnknown(int startindex,int length) {
		for(int i=0;i<length;++i)
			if (instList[startindex + i].isMatched)
				return false;
		return true;
	}

	/**
	 * Calculate an n-gram hash, given a particular hash function
	 * @param gramSize is the size of the n-gram
	 * @param instHash is the first Instruction in the n-gram
	 * @param hashCalc is the hash function
	 * @return the final 32-bit hash
	 * @throws MemoryAccessException
	 */
	public int hashGram(int gramSize,InstructHash instHash,HashCalculator hashCalc) throws MemoryAccessException {
		int hashVal = Hash.SEED;			// Seed the CRC
		for(int i=0;i<gramSize;++i) {
			InstructHash curHash = instList[instHash.index + i];
			hashVal = hashCalc.calcHash(hashVal, curHash.instruction);
		}
		return hashVal;
	}

	/**
	 * Calculate n-gram hashes used for matching (for Instructions in this basic-block).  The exact hashes generated
	 * can be changed to get different looks at the data over multiple matching passes.
	 * @param minLength is the minimum length of an n-gram to calculate
	 * @param maxLength is the maximum length of an n-gram
	 * @param wholeBlock, true indicates a hash of the whole block should be calculated even if its size is below minLength
	 * @param matchOnly, true indicates hashes should only be calculated for previously matched, or small, blocks
	 * @param hashCalc is the hash function for this matching pass
	 * @throws MemoryAccessException
	 */
	protected void calcHashes(int minLength,int maxLength,boolean wholeBlock,boolean matchOnly,HashCalculator hashCalc) throws MemoryAccessException {
		if (wholeBlock && (instList.length < minLength)) {
			// If allowed and if block is too small for even smallest n-gram
			minLength = instList.length;		// Set-up for exactly 1 whole-block n-gram
			maxLength = instList.length;
		}
		else if (matchOnly && matchHash == 0 && instList.length > 8) {
			// If matchOnly, this block has not been matched, and this block is big, then don't generate n-grams for it
			for(int i=0;i<instList.length;++i) {
				if (!instList[i].isMatched)
					instList[i].clearNGrams(0);		// No possibility of matching with tiny pieces
			}
			return;
		}
		for(int i=0;i<instList.length;++i) {		// Calculate hashes starting with instruction i
			if (instList[i].isMatched) continue;	// If already match, no hashes with this instruction
			int maxind;
			if (i + minLength > instList.length) {	// If we cannot fit in minimum hash size
				instList[i].clearNGrams(0);			// No hashes
				continue;
			}
			maxind = i + maxLength;				// Maximum possible index
			if (maxind > instList.length) {		// Make sure it fits
				maxind = instList.length;
			}
			int num = maxind - i - minLength + 1;	// Number of hashes we generate for this instruction
			instList[i].clearNGrams(num);
			// If an n-gram contains the block's starting instruction (and the block is big) this is encoded
			// in the hash by changing the initial hash accumulator value.
			int accum = (i==0 && instList.length > 8) ? Hash.SEED: Hash.ALTERNATE_SEED;	// For big blocks, encode starting instruction
			
			// Perform the intermediate hashes,  0 to minLength-1
			for(int j=0;j<minLength-1;++j) {
				if (accum != 0) {
					if (instList[i+j].isMatched) {		// Could be matched/unmatched instructions in window
						accum = 0;
						break;
					}
					accum = hashCalc.calcHash(accum, instList[i + j].instruction);
				}
			}
			
			// Extend to final hashes, saving the resulting nGram each time
			for(int j=0;j<num;++j) {
				// Hash in one more value
				if (accum != 0) {
					if (instList[i+j+minLength-1].isMatched)
						accum = 0;
					else
						accum = hashCalc.calcHash(accum, instList[i + j + minLength-1].instruction);
				}
				// Create a hash record
				if (accum != 0) {										
					instList[i].nGrams[j] = new Hash(accum ^ matchHash,minLength+j);	// XOR in non-zero value if block has already been matched
				}
				else
					instList[i].nGrams[j] = null;
			}
		}
	}
}

