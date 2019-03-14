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
package ghidra.bitpatterns.gui;

import java.util.Set;

import ghidra.closedpatternmining.ClosedSequenceMiner;
import ghidra.closedpatternmining.FrequentSequence;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for mining closed sequences from byte sequences
 */
public class MineSequenceTask extends Task {

	private Set<FrequentSequence> closedSeqs;
	private ClosedSequenceMiner miner;

	public MineSequenceTask(ClosedSequenceMiner miner) {
		super("Mining Closed Sequences", true, true, true, true);
		this.miner = miner;
	}

	@Override
	public void run(TaskMonitor monitor) {
		closedSeqs = miner.mineClosedSequences(monitor);
	}

	public Set<FrequentSequence> getClosedSeqs() {
		return closedSeqs;
	}

}
