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
 * 
 * Preload search patterns and actions, then call search method.
 */

public class MemoryBytePatternSearcher {
	private static final long RESTRICTED_PATTERN_BYTE_RANGE = 32;

	ArrayList<Pattern> patternList;

	private String searchName = "";

	/**
	 * Create with pre-created patternList
	 * 
	 * @param patternList - list of patterns(bytes/mask/action)
	 */
	public MemoryBytePatternSearcher(String searchName, ArrayList<Pattern> patternList) {
		this.searchName = searchName;
		this.patternList = new ArrayList<Pattern>(patternList);
	}

	/**
	 * Create with no patternList, must add patterns before searching
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

	/**
	 * Search initialized memory blocks for all patterns(bytes/mask/action).
	 * Call associated action for each pattern matched.
	 * 
	 * @param program to be searched
	 * @param searchSet set of bytes to restrict search to
	 * @param monitor allow canceling and reporting of progress
	 * 
	 * @throws CancelledException if canceled
	 */
	public void search(Program program, AddressSetView searchSet, TaskMonitor monitor)
			throws CancelledException {
		SequenceSearchState root = SequenceSearchState.buildStateMachine(patternList);

		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block2 : blocks) {
			MemoryBlock block = block2;
			if (!searchSet.intersects(block.getStart(), block.getEnd())) {
				continue;
			}
			try {
				searchBlock(root, program, block, searchSet, monitor);
			}
			catch (IOException e) {
				Msg.error(this, "Unable to scan block " + block.getName() + " for patterns");
			}
		}
	}

	/**
	 * Search through bytes of a memory block using the finite state machine -root-
	 * Apply any additional rules for matching patterns.
	 * 
	 * @param program is the Program being searched
	 * @param block is the specific block of bytes being searched
	 * 
	 * @throws IOException exception during read of memory
	 * @throws CancelledException canceled search
	 */
	private void searchBlock(SequenceSearchState rootState, Program program, MemoryBlock block,
			AddressSetView restrictSet, TaskMonitor monitor)
			throws IOException, CancelledException {

		// if no restricted set, make restrict set the full block
		AddressSet doneSet = new AddressSet(restrictSet);
		if (doneSet.isEmpty()) {
			doneSet.addRange(block.getStart(), block.getEnd());
		}
		doneSet = doneSet.intersectRange(block.getStart(), block.getEnd());

		Address blockStartAddr = block.getStart();

		// pull each range off the restricted set
		AddressRangeIterator addressRanges = doneSet.getAddressRanges();
		while (addressRanges.hasNext()) {
			monitor.checkCanceled();
			AddressRange addressRange = addressRanges.next();

			monitor.setMessage(searchName + " Search");
			monitor.initialize(doneSet.getNumAddresses());
			monitor.setProgress(0);

			ArrayList<Match> mymatches = new ArrayList<>();

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

			rootState.apply(data, maxBlockSearchLength, mymatches, monitor);
			monitor.checkCanceled();

			monitor.setMessage(searchName + " (Examine Matches)");
			monitor.initialize(mymatches.size());
			monitor.setProgress(0);

			// TODO: DANGER there is much offset<-->address calculation here
			//       should be OK, since they are all relative to the block.
			for (int i = 0; i < mymatches.size(); ++i) {
				monitor.checkCanceled();
				monitor.setProgress(i);
				Match match = mymatches.get(i);
				Address addr = blockStartAddr.add(match.getMarkOffset() + blockOffset);
				if (!match.checkPostRules(streamoffset + blockOffset)) {
					continue;
				}
				MatchAction[] matchactions = match.getMatchActions();

				for (MatchAction matchaction : matchactions) {
					matchaction.apply(program, addr, match);
				}
			}
		}
	}
}
