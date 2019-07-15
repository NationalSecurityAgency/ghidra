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
package ghidra.app.plugin.match;

import generic.stl.Pair;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.search.trie.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class MatchData {
	private MatchData() {
		// non-instantiable
	}

	// Finds one-to-many matches in functions from addressSet A and Address Set B
	public static List<MatchedData> matchData(Program aProgram, AddressSetView setA,
			Program bProgram, AddressSetView setB, int minimumDataSize, int maximumDataSize,
			int alignment, boolean skipHomogenousData, boolean includeOneToOne,
			boolean includeNonOneToOne, TaskMonitor monitor) throws CancelledException {
		if (alignment < 1) {
			alignment = 1;
		}
		setA = removeUninitializedBlocks(aProgram, setA);
		setB = removeUninitializedBlocks(bProgram, setB);

		List<MatchedData> result = new ArrayList<MatchedData>();

		ByteTrieIfc<Pair<Set<Address>, Set<Address>>> sourceTrie =
			extractSourceHashes(aProgram, setA, minimumDataSize, maximumDataSize,
				skipHomogenousData, monitor);

		findDestinationMatches(aProgram, bProgram, setB, minimumDataSize, alignment,
			includeOneToOne, includeNonOneToOne, result, sourceTrie, monitor);

		monitor.setMessage("");
		return result;
	}

	private static ByteTrieIfc<Pair<Set<Address>, Set<Address>>> extractSourceHashes(
			Program aProgram, AddressSetView setA, int minimumDataSize, int maximumDataSize,
			boolean skipHomogenousData, TaskMonitor monitor) throws CancelledException {

		ByteTrieIfc<Pair<Set<Address>, Set<Address>>> trie;
		trie = new ByteTrie<Pair<Set<Address>, Set<Address>>>();

		int numDefinedData = (int) aProgram.getListing().getNumDefinedData();
		monitor.initialize(numDefinedData);
		monitor.setMessage("(1 of 4) Compiling source data");

		DataIterator aProgDataIter = aProgram.getListing().getDefinedData(setA, true);
		while (aProgDataIter.hasNext()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			Data aData = aProgDataIter.next();
			final int length = aData.getLength();
			if (length >= minimumDataSize && length <= maximumDataSize) {
				boolean doHash = true;
				byte[] bytes = null;
				if (skipHomogenousData) {
					boolean different = false;
					try {
						bytes = aData.getBytes();
					}
					catch (MemoryAccessException e) {
						throw new RuntimeException(e);
					}
					byte first = bytes[0];
					for (int ii = 1; ii < bytes.length; ++ii) {
						if (bytes[ii] != first) {
							different = true;
							break;
						}
					}
					doHash = different;
				}
				if (doHash) {
					if (bytes == null) {
						try {
							bytes = aData.getBytes();
						}
						catch (MemoryAccessException e) {
							throw new RuntimeException(e);
						}
					}
					ByteTrieNodeIfc<Pair<Set<Address>, Set<Address>>> node = trie.find(bytes);
					if (node == null || !node.isTerminal()) {
						HashSet<Address> set = new HashSet<Address>();
						set.add(aData.getAddress());
						trie.add(bytes, new Pair<Set<Address>, Set<Address>>(set,
							new HashSet<Address>()));
					}
					else {
						node.getItem().first.add(aData.getAddress());
					}
				}
			}
		}

		return trie;
	}

	private static void findDestinationMatches(Program aProgram, Program bProgram,
			AddressSetView setB, int minimumDataSize, int alignment, boolean includeOneToOne,
			boolean includeNonOneToOne, List<MatchedData> result,
			ByteTrieIfc<Pair<Set<Address>, Set<Address>>> sourceTrie, TaskMonitor monitor)
			throws CancelledException {
		List<SearchResult<Address, Pair<Set<Address>, Set<Address>>>> searchResults;
		try {
			monitor.setMessage("(2 of 4) Search destination bytes");
			searchResults = sourceTrie.search(bProgram.getMemory(), setB, monitor);
		}
		catch (MemoryAccessException e) {
			throw new RuntimeException(e);
		}

		// save time by managing views of data starts and extents in
		// program b
		Listing bListing = bProgram.getListing();
		AddressSet dataExtents = new AddressSet();
		AddressSet dataStarts = new AddressSet();
		DataIterator definedData = bListing.getDefinedData(true);
		while (definedData.hasNext()) {
			Data data = definedData.next();
			dataExtents.add(data.getMinAddress(), data.getMaxAddress());
			dataStarts.add(data.getMinAddress());
		}

		// note that this post-process step is critical; it adds b program locations
		// into the user items in the trie, which is required to properly measure 
		// arity.  if the alignment fails or the b location points into already
		// defined data, the location is omitted
		monitor.initialize(searchResults.size());
		monitor.setMessage("(3 of 4) Post-process search results");
		for (SearchResult<Address, Pair<Set<Address>, Set<Address>>> searchResult : searchResults) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			Address bLocation = searchResult.getPosition();
			if (bLocation.getOffset() % alignment != 0) {
				continue;
			}
			if (!dataStarts.contains(bLocation) && dataExtents.contains(bLocation)) {
				// our match points into the MIDDLE of already defined data
				continue;
			}
			Pair<Set<Address>, Set<Address>> item = searchResult.getItem();
			Set<Address> bLocations = item.second;
			bLocations.add(bLocation);
		}

		generateMatches(result, aProgram, bProgram, searchResults, alignment, includeOneToOne,
			includeNonOneToOne, monitor);
	}

	private static void generateMatches(List<MatchedData> result, Program aProgram,
			Program bProgram,
			List<SearchResult<Address, Pair<Set<Address>, Set<Address>>>> searchResults,
			int alignment, boolean includeOneToOne, boolean includeNonOneToOne, TaskMonitor monitor)
			throws CancelledException {

		HashSet<ByteTrieNodeIfc<Pair<Set<Address>, Set<Address>>>> done =
			new HashSet<ByteTrieNodeIfc<Pair<Set<Address>, Set<Address>>>>();
		Listing aListing = aProgram.getListing();
		Listing bListing = bProgram.getListing();

		monitor.initialize(searchResults.size());
		monitor.setMessage("(4 of 4) Create match objects");
		for (SearchResult<Address, Pair<Set<Address>, Set<Address>>> searchResult : searchResults) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			ByteTrieNodeIfc<Pair<Set<Address>, Set<Address>>> node = searchResult.getNode();
			if (!done.contains(node)) {
				Pair<Set<Address>, Set<Address>> pair = searchResult.getItem();
				Set<Address> aLocations = pair.first;
				Set<Address> bLocations = pair.second;
				final int aSize = aLocations.size();
				final int bSize = bLocations.size();

				boolean processResult =
					(includeOneToOne && aSize == 1 && bSize == 1) ||
						(includeNonOneToOne && (aSize > 1 || bSize > 1));

				if (processResult) {
					for (Address aLocation : aLocations) {
						for (Address bLocation : bLocations) {
							Data aDatum = aListing.getDataAt(aLocation);
							Data bDatum = bListing.getDataAt(bLocation);
							MatchedData matchedData =
								new MatchedData(aProgram, bProgram, aLocation, bLocation, aDatum,
									bDatum, aSize, bSize, null);
							result.add(matchedData);
						}
					}
				}
				done.add(node);
			}
		}
	}

	private static AddressSetView removeUninitializedBlocks(Program program, AddressSetView addrSet) {
		return addrSet.intersect(program.getMemory().getLoadedAndInitializedAddressSet());
	}
}
