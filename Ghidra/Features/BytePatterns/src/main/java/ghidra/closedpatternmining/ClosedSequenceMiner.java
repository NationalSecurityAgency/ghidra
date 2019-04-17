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

import ghidra.util.task.TaskMonitor;

/**
 * This class is for mining patterns (i.e., closed sequences) in collections of sequences 
 * of bytes.
 * 
 * <P> Suppose a sequence S occurs n many times in the database.  S is closed if no proper 
 * supersequence occurs >= n many times in the database.
 * 
 * 
 * <P>The algorithm implemented in this package is based on that in
 * "BIDE: Efficient Mining of Frequent Closed Sequences" by 
 * Wang & Han
 *
 */

public class ClosedSequenceMiner {

	private Set<FrequentSequence> frequentClosedSequences;
	private int minSupport;  //lower bound for how many sequences something must occur in                                      
	private TreeSet<FrequentSequenceItem> globallyFrequentItems;  //items occuring in at least minSupport sequences
	private SequenceDatabase database; //database to mine

	/**
	 * Create a {@link ClosedSequenceMiner} for a particular database
	 * @param database the database to mine
	 * @param minSupport lower bound for number of sequences a frequent item must occur in
	 */
	public ClosedSequenceMiner(SequenceDatabase database, int minSupport) {
		this.minSupport = minSupport;
		frequentClosedSequences = new HashSet<>();
		this.database = database;
	}

	/**
	 * Mine the database for closed sequences.
	 * 
	 * @param monitor
	 * @return The discovered sequences
	 */
	public Set<FrequentSequence> mineClosedSequences(TaskMonitor monitor) {
		globallyFrequentItems = database.getGloballyFrequentItems(minSupport);
		monitor.setMaximum(globallyFrequentItems.size());
		for (FrequentSequenceItem gfItem : globallyFrequentItems) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress(1);
			List<SequenceItem> singletonFrequentItem = new ArrayList<SequenceItem>();
			singletonFrequentItem.add(gfItem.getItem());
			ProjectedDatabase projectedDatabase =
				new ProjectedDatabase(database, singletonFrequentItem);
			Set<FrequentSequenceItem> backwardExtensionItems =
				projectedDatabase.getBackwardExtensionItems();
			if (backwardExtensionItems.size() == 0) {
				bide(projectedDatabase, monitor);
			}
		}
		return frequentClosedSequences;
	}

	/**
	 * "bide" is short for "BiDirectional Extension", the name of the algorithm
	 * in the paper by Wang & Han
	 * @param projectedDatabase
	 * @param monitor 
	 */
	private void bide(ProjectedDatabase projectedDatabase, TaskMonitor monitor) {
		TreeSet<FrequentSequenceItem> locallyFrequentItems =
			projectedDatabase.getLocallyFrequentItems(globallyFrequentItems, minSupport);
		Set<FrequentSequenceItem> forwardExtensionItems =
			projectedDatabase.getForwardExtensionItems(locallyFrequentItems);
		if (forwardExtensionItems.size() == 0) {
			frequentClosedSequences.add(new FrequentSequence(projectedDatabase.getPrefix(),
				projectedDatabase.getSupport()));
		}
		for (FrequentSequenceItem fItem : locallyFrequentItems) {
			if (monitor.isCancelled()) {
				return;
			}
			ProjectedDatabase extended = new ProjectedDatabase(projectedDatabase, fItem.getItem());
			Set<FrequentSequenceItem> backwardExtensionItems = extended.getBackwardExtensionItems();
			if (backwardExtensionItems.size() == 0) {
				bide(extended, monitor);
			}
		}
	}
}
