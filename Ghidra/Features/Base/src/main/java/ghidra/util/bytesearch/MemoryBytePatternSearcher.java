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

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Multi pattern/mask/action memory searcher. This is the legacy memory searcher that specifically
 * uses {@link Pattern} objects which relies on patterns having actions that get invoked as the
 * pattern is found in memory. If you want a simpler, more generic way to search for bulk patterns
 * in memory, you can use the {@link ProgramMemorySearcher}, . If you want an even more generic
 * searcher that isn't restricted to just searching program memory, you can directly use a
 *  {@link BulkPatternSearcher}.
 * <P>
 * In this class, patterns can be given at construction time or added one at a time. Optionally,
 * this class can be called with a pre-built BulkPatternSearcher, which is a bit awkward since
 * it is not compatible with adding patterns later. In that case, a new BulkPatternSearcher will be 
 * created with only the patterns that were added after construction.
 * <P>
 * Once patterns have been added, simply call the search or searchAll methods to perform a search. 
 */

public class MemoryBytePatternSearcher {
	BulkPatternSearcher<Pattern> patternSearcher = null;
	ArrayList<Pattern> patternList;
	private String searchName = "Searching";

	private boolean doExecutableBlocksOnly = false;  // only search executable blocks

	/**
	 * Create with pre-created patternList
	 * @param searchName name of search
	 * @param patternList - list of patterns(bytes/mask/action)
	 */
	public MemoryBytePatternSearcher(String searchName, List<Pattern> patternList) {
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
		patternSearcher = null;
	}

	public void setSearchExecutableOnly(boolean doExecutableBlocksOnly) {
		this.doExecutableBlocksOnly = doExecutableBlocksOnly;
	}

	/**
	 * Search all initialized memory blocks and associated actions on matches
	 * 
	 * @param program to be searched
	 * @param monitor allow canceling and reporting of progress
	 * 
	 * @throws CancelledException if canceled
	 */
	public void searchAll(Program program, TaskMonitor monitor) throws CancelledException {
		search(program, null, monitor);
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

		ProgramMemorySearcher<Pattern> searcher =
			new ProgramMemorySearcher<>(searchName + " Search", program, patternSearcher);

		if (searchSet == null) {
			searchSet = program.getMemory().getAllInitializedAddressSet();
		}
		if (doExecutableBlocksOnly) {
			searchSet = searchSet.intersect(program.getMemory().getExecuteSet());
		}

		searcher.search(searchSet, m -> processMatch(program, m), monitor);
	}

	private void processMatch(Program program, AddressMatch<Pattern> match) {
		Pattern pattern = match.getPattern();
		Address addr = match.getAddress();
		// the post rules seem to work off the offset were the first pattern matched, not where
		// its mark start is. Since the address is at the mark offset, we want to subtract that
		// back out
		long rawPatternOffset = addr.getOffset() - pattern.getMarkOffset();
		if (!pattern.checkPostRules(rawPatternOffset)) {
			return;
		}

		MatchAction[] matchactions = pattern.getMatchActions();
		preMatchApply(matchactions, addr);
		for (MatchAction matchaction : matchactions) {
			matchaction.apply(program, addr, match);
		}

		postMatchApply(matchactions, addr);
	}

	/**
	 * Called just before any match rules are applied.
	 * @param actions the actions from the pattern that matched
	 * @param address address of match
	 */
	public void preMatchApply(MatchAction[] actions, Address address) {
		// override if any initialization needs to be done before rule application
	}

	/**
	 * Called just after any match rules are applied.
	 * Can be used for cross post rule matching state application and cleanup.
	 * @param actions the actions from the pattern that matched
	 * @param address the address of match
	 */
	public void postMatchApply(MatchAction[] actions, Address address) {
		// override if any cleanup from rule match application is needed
	}
}
