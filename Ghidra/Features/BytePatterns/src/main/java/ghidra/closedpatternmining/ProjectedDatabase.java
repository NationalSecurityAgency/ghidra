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
package ghidra.closedpatternmining;

import java.util.*;
import java.util.Map.Entry;

/**
 * 
 * A ProjectedDatabase contains all the suffixes of strings in database
 * which have a prefix consistent with prefixSequence
 *
 */
public class ProjectedDatabase {

	private SequenceDatabase database;  //the database to project from
	private List<SequenceItem> prefixSequence;  //the initial sequence
	private List<ProjectedSequenceInfo> projectedInfo;
	private int support;

	/**
	 * Constructs a {@link ProjectedDatabase} given a database and a prefix sequence
	 * 
	 * <p> Note: {@code prefixSequence} is assumed to be in ascending order of Item index
	 * @param database database to project
	 * @param prefixSequence prefix to use in projection
	 */
	public ProjectedDatabase(SequenceDatabase database, List<SequenceItem> prefixSequence) {
		this.prefixSequence = prefixSequence;
		this.database = database;
		projectedInfo = new ArrayList<ProjectedSequenceInfo>();
		int numSequences = database.getSequences().size();

		//don't use for-each over database.getSequences because we actually
		//need to know what i is
		for (int i = 0; i < numSequences; ++i) {
			Sequence seq = database.getSequences().get(i);
			int projectedIndex = seq.getIndexAfterFirstInstance(prefixSequence);
			//if the projection leaves the empty string, record anyway
			//is this the correct thing to do?
			if (projectedIndex != -1) {// && projectedIndex != database.getSequenceLength()){
				ProjectedSequenceInfo projSeq = new ProjectedSequenceInfo(i, projectedIndex);
				projectedInfo.add(projSeq);
				support += seq.getCount();
			}
		}
	}

	/**
	 * Given a {@link ProjectedDatabase}, construct a new {@link ProjectedDatabase} by
	 * adding one item to the prefix sequence.
	 * 
	 * @param projDatabase projected database to extend
	 * @param extendingItem item to extend by
	 */
	public ProjectedDatabase(ProjectedDatabase projDatabase, SequenceItem extendingItem) {
		List<SequenceItem> initialList = projDatabase.getPrefix();
		SequenceItem lastItem = initialList.get(initialList.size() - 1);
		if (lastItem.getIndex() >= extendingItem.getIndex()) {
			throw new IllegalArgumentException(
				"extending item must be after all items of the prefixSequence of projDatabase!");
		}

		database = projDatabase.getDatabase();

		prefixSequence = new ArrayList<>(initialList);
		prefixSequence.add(extendingItem);

		projectedInfo = new ArrayList<ProjectedSequenceInfo>();
		List<Sequence> sequences = database.getSequences();
		support = 0;
		int indexToCheck = extendingItem.getIndex();
		String symbolToFind = extendingItem.getSymbol();
		for (ProjectedSequenceInfo projSeq : projDatabase.getProjectedInfo()) {
			Sequence sequence = sequences.get(projSeq.getSequenceIndex());
			String seqAsString = sequence.getSequenceAsString();
			if (seqAsString.substring(indexToCheck, indexToCheck + 1).equals(symbolToFind)) {
				support += sequence.getCount();
				ProjectedSequenceInfo extendedSequence =
					new ProjectedSequenceInfo(projSeq.getSequenceIndex(), indexToCheck + 1);
				projectedInfo.add(extendedSequence);
			}
		}
	}

	/**
	 * Get the database
	 * @return database
	 */
	public SequenceDatabase getDatabase() {
		return database;
	}

	/**
	 * Get the prefix sequence
	 * @return prefix sequence
	 */
	public List<SequenceItem> getPrefix() {
		return prefixSequence;
	}

	/**
	 * Get projection data
	 * @return projected info
	 */
	public List<ProjectedSequenceInfo> getProjectedInfo() {
		return projectedInfo;
	}

	//for testing
	Set<String> getProjectedSequencesAsSet() {
		if (projectedInfo == null) {
			return null;
		}
		HashSet<String> projectedSeqs = new HashSet<String>();
		for (ProjectedSequenceInfo projSeq : projectedInfo) {
			Sequence seq = database.getSequences().get(projSeq.getSequenceIndex());
			String seqString = seq.getSequenceAsString();
			int end = seqString.length();
			int begin = Math.min(projSeq.getProjectedIndex(), end);
			projectedSeqs.add(seqString.substring(begin, end));
		}
		return projectedSeqs;
	}

	/**
	 * Returns the number of sequences in the projected database
	 * @return number of sequences
	 */
	public int getSupport() {
		return support;
	}

	/**
	 * Returns a set of {@link FrequentSequenceItem}s composed of all {@link FrequentSequenceItem}s in {@code globallyFrequentItems} 
	 * which occur after the projection index and in at least {@code minSupport} sequences in the projected database.
	 * @param globallyFrequentItems
	 * @param minSupport 
	 * @return
	 */
	public TreeSet<FrequentSequenceItem> getLocallyFrequentItems(Set<FrequentSequenceItem> globallyFrequentItems,
			int minSupport) {
		Map<SequenceItem, Integer> frequentItemBag = new HashMap<SequenceItem, Integer>();
		for (ProjectedSequenceInfo currentProjSeq : projectedInfo) {
			for (FrequentSequenceItem globFreqItem : globallyFrequentItems) {
				SequenceItem globalItem = globFreqItem.getItem();
				int index = globalItem.getIndex();
				if (index < currentProjSeq.getProjectedIndex()) {
					continue;//the globally frequent item is in a position in the prefix, no need to check
				}
				Sequence fullSequence =
					database.getSequences().get(currentProjSeq.getSequenceIndex());
				String symbol = fullSequence.getSequenceAsString().substring(index, index + 1);

				if (!symbol.equals(globalItem.getSymbol())) {
					continue;//symbols are different, check next item
				}

				Integer count = frequentItemBag.get(globalItem);
				if (count == null) {
					frequentItemBag.put(globalItem, new Integer(fullSequence.getCount()));
				}
				else {
					frequentItemBag.put(globalItem, count + fullSequence.getCount());
				}
			}
		}

		TreeSet<FrequentSequenceItem> frequentItemSet = new TreeSet<FrequentSequenceItem>();
		for (Entry<SequenceItem, Integer> itemAndCount : frequentItemBag.entrySet()) {
			int count = itemAndCount.getValue();
			if (count >= minSupport) {
				frequentItemSet.add(new FrequentSequenceItem(count, itemAndCount.getKey()));
			}
		}
		return frequentItemSet;
	}

	/**
	 * Returns the subset of {@code locallyFrequentItems} which occur in all sequences in the
	 * projected database
	 * @param locallyFrequentItems {@code FrequentItem}s to check
	 * @return {@code FrequentItem}s which occur in all sequence in projected database
	 */
	public Set<FrequentSequenceItem> getForwardExtensionItems(Set<FrequentSequenceItem> locallyFrequentItems) {
		Set<FrequentSequenceItem> localExtensionItems = new HashSet<FrequentSequenceItem>();
		for (FrequentSequenceItem fItem : locallyFrequentItems) {
			if (fItem.getSupport() == support) {
				localExtensionItems.add(fItem);
			}
		}
		return localExtensionItems;
	}

	/**
	 * Computes the set of backward extension items, i.e., any items that could fill empty
	 * spaces in the projected sequence without changing the support.
	 * 
	 * <p> For example, if you create a {@link ProjectedDatabase} with the prefix A.C, and all of the
	 * resulting sequences happen to have a B in the second position (i.e. position 1), the 
	 * returned set would consist of the {@link FrequentSequenceItem} with {@link SequenceItem (B,1)}
	 * @return backward extension items
	 */
	public Set<FrequentSequenceItem> getBackwardExtensionItems() {
		Set<FrequentSequenceItem> backwardExtensionItems = new HashSet<FrequentSequenceItem>();
		if (projectedInfo.size() == 0) {
			return backwardExtensionItems;
		}

		//record what the first sequence has at each ditted position
		Map<Integer, String> positionsToSymbols = new HashMap<Integer, String>();
		int dittedPosition = 0;
		List<Sequence> sequences = database.getSequences();
		Sequence firstSequence = sequences.get(projectedInfo.get(0).getSequenceIndex());
		for (SequenceItem currentItem : prefixSequence) {
			int fixedPosition = currentItem.getIndex();
			while (dittedPosition < fixedPosition) {
				String symbol = firstSequence.getSequenceAsString().substring(dittedPosition,
					dittedPosition + 1);
				//System.out.println("adding " + symbol + " at position " + dittedPosition);
				positionsToSymbols.put(new Integer(dittedPosition), symbol);
				dittedPosition++;
			}
			dittedPosition++;//advance past fixedPosition
		}

		//if all of the preceeding positions are filled, there can't be any backward
		//extension items
		if (positionsToSymbols.isEmpty()) {
			return backwardExtensionItems;
		}

		//check the other projected sequences for consistency with the first sequence
		//if there is an inconsistency, that position can't be a backward extension item
		int numSequences = projectedInfo.size();
		for (int i = 1; i < numSequences; ++i) {
			Set<Integer> positionsToRemove = new HashSet<Integer>();
			for (Entry<Integer, String> entry : positionsToSymbols.entrySet()) {
				Integer key = entry.getKey();
				String storedValue = entry.getValue();
				Sequence testSequence = sequences.get(projectedInfo.get(i).getSequenceIndex());
				String testValue = testSequence.getSequenceAsString().substring(key, key + 1);
				if (!storedValue.equals(testValue)) {
					positionsToRemove.add(key);
				}
			}
			for (Integer position : positionsToRemove) {
				positionsToSymbols.remove(position);
			}
			//exit early if we find that there are conflicting choices for all ditted positions
			if (positionsToSymbols.isEmpty()) {
				return backwardExtensionItems;
			}
		}

		//return the set FrequentItems corresponding to all positions which are not specified
		//in the prefix but which nonetheless have the same value for all projected sequences
		for (Entry<Integer, String> entry : positionsToSymbols.entrySet()) {
			int position = entry.getKey();
			String symbol = entry.getValue();
			SequenceItem item = new SequenceItem(symbol, position);
			FrequentSequenceItem fItem = new FrequentSequenceItem(support, item);
			backwardExtensionItems.add(fItem);
		}
		return backwardExtensionItems;
	}
}
