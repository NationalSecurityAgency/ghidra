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
package ghidra.util.bytesearch;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Multi pattern/mask/action memory searcher
 * Patterns must be supplied/added, or a pre-initialized searchState supplied
 * 
 * Preload search patterns and actions, then call search method.
 */

public class MemoryBytePatternSearcher {
	private static final long RESTRICTED_PATTERN_BYTE_RANGE = 32;

	BulkPatternSearcher<Pattern> patternSearcher = null;

	ArrayList<Pattern> patternList;

	private String searchName = "";

	private boolean doExecutableBlocksOnly = false;  // only search executable blocks

	private long numToSearch = 0;
	private long numSearched = 0;

	/**
	 * Create with pre-created patternList
	 * @param searchName name of search
	 * @param patternList - list of patterns(bytes/mask/action)
	 */
	public MemoryBytePatternSearcher(String searchName, ArrayList<Pattern> patternList) {
		this.searchName = searchName;
		this.patternList = new ArrayList<Pattern>(patternList);
	}

	/**
	 * Create with an initialized BulkPatternSearcher
	 * @param searchName name of search
	 * @param searcher search state pre-initialized
	 */
	public MemoryBytePatternSearcher(String searchName, BulkPatternSearcher<Pattern> searcher) {
		this.searchName = searchName;
		this.patternSearcher = searcher;
	}

	/**
	 * Create with no patternList, must add patterns before searching
	 * @param searchName name of search
	 * 
	 */
	public MemoryBytePatternSearcher(String searchName) {
		this.searchName = searchName;
		patternList = new ArrayList<>();
	}

	/**
	 * Add a search pattern 
	 * @param pattern - pattern(bytes/mask/action)
	 */
	public void addPattern(Pattern pattern) {
		patternList.add(pattern);
	}

	public void setSearchExecutableOnly(boolean doExecutableBlocksOnly) {
		this.doExecutableBlocksOnly = doExecutableBlocksOnly;
	}

	/**
	 * Search initialized memory blocks for all patterns(bytes/mask/action).
	 * Call associated action for each pattern matched.
	 * 
	 * @param program to be searched
	 * @param searchSet set of bytes to restrict search, if null or empty then search all memory blocks
	 * @param monitor allow canceling and reporting of progress
	 * 
	 * @throws CancelledException if canceled
	 */
	public void search(Program program, AddressSetView searchSet, TaskMonitor monitor)
			throws CancelledException {
		if (patternSearcher == null) {
			patternSearcher = new BulkPatternSearcher<>(patternList);
		}

		numToSearch = getNumToSearch(program, searchSet);
		monitor.setMessage(searchName + " Search");
		monitor.initialize(numToSearch);

		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			monitor.setProgress(numSearched);
			// check if entire block has anything that is searchable
			if (!block.isInitialized()) {
				continue;
			}
			if (doExecutableBlocksOnly && !block.isExecute()) {
				continue;
			}
			if (searchSet != null && !searchSet.isEmpty() &&
				!searchSet.intersects(block.getStart(), block.getEnd())) {
				continue;
			}

			try {
				searchBlock(patternSearcher, program, block, searchSet, monitor);
			}
			catch (IOException e) {
				Msg.error(this, "Unable to scan block " + block.getName() + " for " + searchName);
			}
			numSearched += block.getSize();
		}
	}

	private long getNumToSearch(Program program, AddressSetView searchSet) {
		long numAddresses = 0;
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			// check if entire block has anything that is searchable
			if (!block.isInitialized()) {
				continue;
			}
			if (doExecutableBlocksOnly && !block.isExecute()) {
				continue;
			}
			if (searchSet != null && !searchSet.isEmpty() &&
				!searchSet.intersects(block.getStart(), block.getEnd())) {
				continue;
			}
			numAddresses += block.getSize();
		}
		return numAddresses;
	}

	/**
	 * Search through bytes of a memory block using the finite state machine (BulkPatterMatcher)
	 * Apply any additional rules for matching patterns.
	 * 
	 * @param program is the Program being searched
	 * @param block is the specific block of bytes being searched
	 * 
	 * @throws IOException exception during read of memory
	 * @throws CancelledException canceled search
	 */
	private void searchBlock(BulkPatternSearcher<Pattern> searcher, Program program,
			MemoryBlock block, AddressSetView restrictSet, TaskMonitor monitor)
			throws IOException, CancelledException {

		// if no restricted set, make restrict set the full block
		AddressSet doneSet;
		if (restrictSet == null || restrictSet.isEmpty()) {
			doneSet = new AddressSet(block.getStart(), block.getEnd());
		}
		else {
			doneSet = restrictSet.intersectRange(block.getStart(), block.getEnd());
		}

		long numInDoneSet = doneSet.getNumAddresses();
		long numInBlock = block.getSize();

		Address blockStartAddr = block.getStart();

		// pull each range off the restricted set
		long progress = monitor.getProgress();
		AddressRangeIterator addressRanges = doneSet.getAddressRanges();
		long numDone = 0;
		while (addressRanges.hasNext()) {
			monitor.checkCancelled();
			monitor.setMessage(searchName + " Search");
			monitor.setProgress(progress + (long) (numInBlock * ((float) numDone / numInDoneSet)));
			AddressRange addressRange = addressRanges.next();
			long numAddressesInRange = addressRange.getLength();

			ArrayList<Match<Pattern>> mymatches = new ArrayList<>();

			long streamoffset = blockStartAddr.getOffset();

			// Give block a starting/ending point before this address to search
			//    patterns might start before, since they have a pre-pattern
			// TODO: this is dangerous, since pattern might be very big, but the set should be restricted
			//       normally only when we are searching for more matching patterns that had a postrule that didn't satisfy
			//       normally the whole memory blocks will get searched.
			long blockOffset = addressRange.getMinAddress().subtract(blockStartAddr);
			blockOffset = blockOffset - RESTRICTED_PATTERN_BYTE_RANGE;
			if (blockOffset <= 0) {
				// don't go before the block start
				blockOffset = 0;
			}

			// compute number of bytes in the range + 1, and don't search more than that.
			long maxBlockSearchLength =
				addressRange.getMaxAddress().subtract(blockStartAddr) - blockOffset + 1;

			InputStream data = block.getData();
			data.skip(blockOffset);

			searcher.search(data, maxBlockSearchLength, mymatches, monitor);
			monitor.checkCancelled();

			monitor.setMessage(searchName + " (Examine Matches)");

			// TODO: DANGER there is much offset<-->address calculation here
			//       should be OK, since they are all relative to the block.
			long matchProgress = progress + (long) (numInBlock * ((float) numDone / numInDoneSet));
			for (int i = 0; i < mymatches.size(); ++i) {
				monitor.checkCancelled();
				monitor.setProgress(
					matchProgress + (long) (numAddressesInRange * ((float) i / mymatches.size())));
				Match<Pattern> match = mymatches.get(i);
				Pattern pattern = match.getPattern();
				Address addr =
					blockStartAddr.add(pattern.getMarkOffset() + match.getStart() + blockOffset);
				long totalOffset = streamoffset + blockOffset + match.getStart();
				if (!pattern.checkPostRules(totalOffset)) {
					continue;
				}

				MatchAction[] matchactions = pattern.getMatchActions();
				preMatchApply(matchactions, addr);
				for (MatchAction matchaction : matchactions) {
					matchaction.apply(program, addr, match);
				}

				postMatchApply(matchactions, addr);
			}

			numDone += numAddressesInRange;
		}
	}

	/**
	 * Called before any match rules are applied
	 * @param matchactions actions that matched
	 * @param addr address of match
	 */
	public void preMatchApply(MatchAction[] matchactions, Address addr) {
		// override if any initialization needs to be done before rule application
	}

	/**
	 * Called after any match rules are applied
	 * Can use for cross post rule matching state application and cleanup.
	 * @param matchactions actions that matched
	 * @param addr adress of match
	 */
	public void postMatchApply(MatchAction[] matchactions, Address addr) {
		// override if any cleanup from rule match application is needed
	}
}
