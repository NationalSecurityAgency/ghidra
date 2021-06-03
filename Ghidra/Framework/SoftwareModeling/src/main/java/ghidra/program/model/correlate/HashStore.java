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
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * HashStore is a sorted, basic-block aware, store for Instruction "n-grams" to help quickly match similar
 * sequences of Instructions between two functions.  The Instructions comprising a single n-gram are hashed
 * for quick lookup by the main matching algorithm (HashedFunctionAddressCorrelation).  Hash diversity is
 * important to minimize collisions, even though the number of hashes calculated for a single function pair
 * match is small.
 * 
 * Hashes are built and sorted respectively using the calcHashes() and insertHashes() methods. The main sort
 * is on the number of collisions for a hash (indicating that there are duplicate or near duplicate instruction
 * sequences), the hashes with fewer (or no) duplicates come first. The secondary sort is on
 * "n", the number of Instructions in the n-gram, which effectively describes the significance of the match, or how
 * unlikely the match is to occur at random.  The main matching algorithm effectively creates a HashSort for both
 * functions, and then in a loop calls
 *    hash = getFirstEntry()    on one side to get the most significant possible match
 *    getEntry(has)             to see if there is a matching n-gram on the other side
 *    
 * If there is a match it is declared to the sort with the matchHash() call, allowing overlapping n-grams to be
 * removed and deconflicting information to be updated.  If there is no match, hashes can be removed with the
 * removeHash() method to allow new hashes to move to the top of the sort.
 * 
 * The store uses a couple of methods to help deconflict very similar sequences of instructions within the same function.
 * Primarily, the sort is basic-block aware.  All n-grams are contained within a single basic block, and when an initial
 * match is found, hashes for other n-grams within that block (and its matching block on the other side) are modified
 * so that n-grams within that block pair can only match each other. 
 *
 */
public class HashStore {
	/**
	 * Comparator for the main HashStore sort.  Sort first preferring smallest number of duplicate n-grams,
	 * then subsort on the size (significance) of the n-gram.
	 *
	 */
	private static class HashOrderComparator implements Comparator<HashEntry> {

		@Override
		public int compare(HashEntry o1, HashEntry o2) {
			int sz1 = o1.instList.size();
			int sz2 = o2.instList.size();
			if (sz1 != sz2) return (sz1 < sz2) ? -1 : 1;
			if (o1.hash.size != o2.hash.size)
				return (o1.hash.size > o2.hash.size) ? -1 : 1;		// Prefer BIGGER n-gram
			return Long.compare(o1.hash.value, o2.hash.value);
		}		
	}

	/**
	 * Class explicitly labeling (one-side of) a matching n-gram pair.
	 *
	 */
	public static class NgramMatch {
		public Block block;				// The block in which the n-gram match occurs
		public int startindex;			// Index of first instruction in the match
		public int endindex;			// Index of the last instruction in the match
	}

	private Program program;
	private Function function;
	private TaskMonitor monitor;
	private TreeMap<Address,Block> blockList;	// All blocks for a function
	private TreeMap<Hash,HashEntry> hashSort;	// HashEntrys sorted by Hash
	private TreeSet<HashEntry> matchSort;		// same HashEntrys in preferred order for matching strategy
	private int matchedBlockCount;				// Count of blocks that have been matched
	private int matchedInstructionCount;		// Count of instructions that have been matched so far
	private int totalInstructions;				// Total number of instructions in function

	public HashStore(Function a,TaskMonitor mon) throws CancelledException {
		function = a;
		program = a.getProgram();
		monitor = mon;
		blockList = new TreeMap<Address,Block>();
		hashSort = new TreeMap<Hash,HashEntry>();
		matchSort = new TreeSet<HashEntry>(new HashOrderComparator());
		matchedBlockCount = 0;			// No matches yet
		matchedInstructionCount = 0;
		totalInstructions = 0;			// basic-blocks and instructions not modeled yet
		initializeStructures();			// Model basic-blocks and instructions
	}

	/**
	 * @return total number of Instructions in the whole function
	 */
	public int getTotalInstructions() { return totalInstructions; }
	
	/**
	 * @return number of instructions that have been matched so far
	 */
	public int numMatchedInstructions() { return matchedInstructionCount; }

	/**
	 * Set up the basic-block and instruction model and the accompanying hash containers
	 * @throws CancelledException
	 */
	private void initializeStructures() throws CancelledException {
		BasicBlockModel blockModel = new BasicBlockModel(program);
		CodeBlockIterator iter = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
		while(iter.hasNext()) {
			CodeBlock block = iter.next();
			createBlock(block);
		}
	}
	
	/**
	 * Create the basic Block structure, walk the Instructions creating InstructHash structures
	 * @param codeBlock	is the set of instruction addresses corresponding to the basic block
	 */
	private void createBlock(CodeBlock codeBlock) {
		Block res = new Block(codeBlock);			// Create hash container for underlying CodeBlock
		ArrayList<InstructHash> instList = new ArrayList<InstructHash>();
		Listing listing = program.getListing();
		Iterator<AddressRange> iter = codeBlock.iterator(true);
		int index = 0;
		while(iter.hasNext()) {						// Iterate over every Instruction in the Block
			AddressRange range = iter.next();
			Address cur = range.getMinAddress();
			Address max = range.getMaxAddress();
			while(cur.compareTo(max) <= 0) {		// Inclusive of final address
				Instruction instruct = listing.getInstructionAt(cur);
				if (instruct != null) {
					InstructHash instHash = new InstructHash(instruct,res,index);		// Build Instruction hash container
					instList.add(instHash);
					index += 1;
					totalInstructions += 1;
					cur = cur.add(instruct.getLength());
				}
				else
					cur = cur.next();
			}
		}
		res.instList = new InstructHash[instList.size()];		// Attach Instruction array to Block
		instList.toArray(res.instList);
		blockList.put(codeBlock.getFirstStartAddress(),res);
	}

	/**
	 * Low level insert of an n-gram into the HashStore
	 * @param curHash  is hash of the n-gram
	 * @param instHash is (starting Instruction of) the n-gram
	 */
	private void insertNGram(Hash curHash,InstructHash instHash) {
		HashEntry entry = hashSort.get(curHash);		// Have we seen this hash before
		if (entry == null) {							// If not,
			entry = new HashEntry(curHash);				// create a new entry
			hashSort.put(curHash, entry);
		}
		else
			matchSort.remove(entry);					// Remove old entry, so we can affect its sort position
		entry.instList.add(instHash);					// add the new n-gram
		instHash.hashEntries.put(curHash, entry);		// cross-reference this entry via the n-gram
		matchSort.add(entry);							// (Re)insert the hash into the sort
	}
	

	/**
	 * Insert all n-gram hashes for a particular instruction
	 * @param instHash is the instruction
	 */
	private void insertInstructionNGrams(InstructHash instHash) {
		for(int i=0;i<instHash.nGrams.length;++i) {
			Hash curHash = instHash.nGrams[i];
			if (curHash == null) break;
			insertNGram(curHash,instHash);
		}
	}
	
	/**
	 * Low level removal of a particular n-gram from the sort 
	 * @param instHash is (starting instruction) of the n-gram
	 * @param curHash is hash (and size) of the n-gram
	 */
	private void removeNGram(InstructHash instHash,Hash curHash) {
		HashEntry hashEntry = instHash.hashEntries.remove(curHash);
		matchSort.remove(hashEntry);			// Remove from matchSort before modifying instList
		hashEntry.instList.remove(instHash);
		if (hashEntry.instList.isEmpty())
			hashSort.remove(curHash);
		else
			matchSort.add(hashEntry);			// Now that instList is updated, reinsert
	}

	/**
	 * Remove all n-grams associated with a particular instruction
	 * @param instHash is the particular instruction
	 */
	private void removeInstructionNGrams(InstructHash instHash) {
		for(int i=0;i<instHash.nGrams.length;++i) {
			Hash curHash = instHash.nGrams[i];
			if (curHash == null) continue;
			HashEntry hashEntry = instHash.hashEntries.get(curHash);
			if (hashEntry == null) continue;
			matchSort.remove(hashEntry);	// Remove from matchSort before modifying instList
			hashEntry.instList.remove(instHash);
			if (hashEntry.instList.isEmpty())
				hashSort.remove(curHash);
			else
				matchSort.add(hashEntry);		// reinsert after update
		}
	}
	
	/**
	 * Remove a particular HashEntry.  This may affect multiple instructions.
	 * @param hashEntry is the entry
	 */
	public void removeHash(HashEntry hashEntry) {
		matchSort.remove(hashEntry);
		hashSort.remove(hashEntry.hash);
		Iterator<InstructHash> iter = hashEntry.instList.iterator();
		while(iter.hasNext()) {
			InstructHash instruct = iter.next();
			instruct.hashEntries.remove(hashEntry.hash);
		}
	}
	
	/**
	 * Calculate hashes for all blocks
	 * @param minLength is the minimum length of an n-gram for these passes
	 * @param maxLength is the maximum length of an n-gram for these passes
	 * @param wholeBlock if true, allows blocks that are smaller than the minimum length to be considered as 1 n-gram.
	 * @param matchOnly if true, only generates n-grams for sequences in previously matched blocks
	 * @param hashCalc is the hash function
	 * @throws MemoryAccessException
	 */
	public void calcHashes(int minLength,int maxLength,boolean wholeBlock,boolean matchOnly,HashCalculator hashCalc) throws MemoryAccessException {
		for(Block block : blockList.values())
			block.calcHashes(minLength,maxLength,wholeBlock,matchOnly,hashCalc);
	}
	
	/**
	 * Insert all hashes associated with unknown (i.e not matched) blocks and instructions 
	 */
	public void insertHashes() {
		for(Block block : blockList.values()) {
			for(int j=0;j<block.instList.length;++j) {
				InstructHash instruct = block.instList[j];
				if (instruct.isMatched) continue;
				insertInstructionNGrams(instruct);
			}
		}
	}
	
	/**
	 * Mark a particular n-gram hash and instruction as having a match.
	 * Set of instructions covered by n-gram are removed, and data structures are updated
	 * @param match	is the n-gram being declared as a match
	 * @param instResult	collects the explicit set of Instructions matched
	 * @param blockResult   collects the explicit set of CodeBlocks matched
	 */
	public void matchHash(NgramMatch match,List<Instruction> instResult,List<CodeBlock> blockResult) {
		Block block = match.block;
		for(int index=match.startindex;index<=match.endindex;++index) {	// For every instruction involved in this n-gram
			InstructHash curInstruct = block.instList[index];
			instResult.add(curInstruct.instruction);			// Store match explicitly
			matchedInstructionCount += 1;
			curInstruct.isMatched = true;						// Mark record as matched
			removeInstructionNGrams(curInstruct);
			curInstruct.nGrams = null;			// Free up memory we won't use anymore
		}
		if (block.isMatched) return;				// Is this the first time we matched this block
		matchedBlockCount += 1;						// Count our block match
		block.setMatched(matchedBlockCount);
		blockResult.add(block.origBlock);			// Store match explicitly
		for(int i=0;i<block.instList.length;++i) {
			InstructHash curInstruct = block.instList[i];
			if (curInstruct.isMatched) continue;		// For each remaining unknown instruction
			for(int j=0;j<curInstruct.nGrams.length;++j) {
				Hash curHash = curInstruct.nGrams[j];
				if (curHash == null) continue;
				HashEntry curEntry = curInstruct.hashEntries.get(curHash);
				if (curEntry == null) continue;				// For each hash still in the pool
				removeNGram(curInstruct,curHash);		// Remove from the store
				int newValue = curHash.value ^ block.getMatchHash();		// Update hash to reflect matched block
				curHash = new Hash(newValue,curHash.size);
				curInstruct.nGrams[j] = curHash;
				insertNGram(curHash,curInstruct);			// Reinsert the hash
			}
		}
	}

	/**
	 * Try to extend a match on a pair of n-grams to the Instructions right before and right after the n-gram.
	 * The match is extended if the Instruction adjacent to the n-gram, and its corresponding pair on the other side,
	 * hash to the same value using the hash function. The NgramMatch objects are updated to reflect the
	 * original n-gram match plus any additional extension.
	 * @param nGramSize	is the original size of the matching n-gram.
	 * @param srcInstruct is the first Instruction in the "source" n-gram
	 * @param srcMatch is the "source" NgramMatch object to be populate
	 * @param destInstruct is the first Instruction in the "destination" n-gram
	 * @param destMatch is the "destination" NgramMatch object to populate
	 * @param hashCalc is the hash function object
	 * @throws MemoryAccessException
	 */
	public static void extendMatch(int nGramSize,InstructHash srcInstruct,NgramMatch srcMatch,
								InstructHash destInstruct,NgramMatch destMatch,HashCalculator hashCalc) throws MemoryAccessException {
		srcMatch.block = srcInstruct.block;
		srcMatch.startindex = srcInstruct.index;
		srcMatch.endindex = srcMatch.startindex + nGramSize -1;
		destMatch.block = destInstruct.block;
		destMatch.startindex = destInstruct.index;
		destMatch.endindex = destMatch.startindex + nGramSize - 1;
		// Try to extend to earlier instructions
		while(srcMatch.startindex > 0 && destMatch.startindex > 0) {		// Can't go past beginning of block
			InstructHash curSrcInstruct = srcMatch.block.instList[srcMatch.startindex-1];
			InstructHash curDestInstruct = destMatch.block.instList[destMatch.startindex-1];
			if (curSrcInstruct.isMatched) break;		// If Instruction already matched, can't extend
			if (curDestInstruct.isMatched) break;
			int srcVal = Hash.ALTERNATE_SEED;		// Seed the hash function
			int destVal = Hash.ALTERNATE_SEED;
			srcVal = hashCalc.calcHash(srcVal, curSrcInstruct.instruction);
			destVal = hashCalc.calcHash(destVal, curDestInstruct.instruction);
			if (srcVal != destVal) break;		// Compare hashes, if they differ, we can't extend
			srcMatch.startindex -= 1;
			destMatch.startindex -= 1;
		}
		// Try to extend to later instructions
		int srcMax = srcMatch.block.instList.length -1;
		int destMax = destMatch.block.instList.length -1;
		while(srcMatch.endindex < srcMax && destMatch.endindex < destMax) {	// Can't go past end of block
			InstructHash curSrcInstruct = srcMatch.block.instList[srcMatch.endindex+1];
			InstructHash curDestInstruct = destMatch.block.instList[destMatch.endindex+1];
			if (curSrcInstruct.isMatched) break;		// If Instruction already matched, can't extend
			if (curDestInstruct.isMatched) break;
			int srcVal = Hash.ALTERNATE_SEED;		// Seed the hash function
			int destVal = Hash.ALTERNATE_SEED;
			srcVal = hashCalc.calcHash(srcVal,curSrcInstruct.instruction);
			destVal = hashCalc.calcHash(destVal, curDestInstruct.instruction);
			if (srcVal != destVal) break;		// Compare hashes, if they differ, we can't extend
			srcMatch.endindex += 1;
			destMatch.endindex += 1;
		}
	}

	/**
	 * @return list of unmatched instructions across the whole function
	 */
	public List<Instruction> getUnmatchedInstructions() {
		LinkedList<Instruction> res = new LinkedList<Instruction>();
		for(Block block : blockList.values()) {
			for(InstructHash instHash : block.instList) {
				if (!instHash.isMatched)
					res.add(instHash.instruction);
			}
		}
		return res;
	}

	/**
	 * Clear the main sort structures, but preserve blocks and instructions
	 */
	public void clearSort() {
		hashSort.clear();
		matchSort.clear();
		for(Block block : blockList.values()) {
			block.clearSort();
		}
	}

	/**
	 * @return true if there are no n-grams left in the sort
	 */
	public boolean isEmpty() {
		return matchSort.isEmpty();
	}

	/**
	 * @return the first HashEntry in the sort.  The least number of matching n-grams and the biggest n-gram.
	 */
	public HashEntry getFirstEntry() {
		return matchSort.first();
	}
	
	/**
	 * Get the HashEntry corresponding to a given hash
	 * @param hash is the Hash to match
	 * @return the set of n-grams (HashEntry) matching this hash
	 */
	public HashEntry getEntry(Hash hash) {
		return hashSort.get(hash);
	}
	
	/**
	 * Get the basic-block with the corresponding start Address
	 * @param addr is the starting address
	 * @return the Block object
	 */
	public Block getBlock(Address addr) {
		return blockList.get(addr);
	}
	
	/**
	 * @return the TaskMonitor for this store
	 */
	public TaskMonitor getMonitor() {
		return monitor;
	}
}
