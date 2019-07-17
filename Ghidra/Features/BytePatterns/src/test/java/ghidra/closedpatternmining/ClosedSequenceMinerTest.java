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

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.task.TaskMonitor;

public class ClosedSequenceMinerTest extends AbstractGenericTest {

	@Test
	public void test1() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("B", 2));
		SequenceDatabase database = new SequenceDatabase(sequences, 1);
		ClosedSequenceMiner miner = new ClosedSequenceMiner(database, 2);
		Set<FrequentSequence> closedSeqs = miner.mineClosedSequences(TaskMonitor.DUMMY);
		assertEquals(1, closedSeqs.size());

		List<SequenceItem> closedSeq1 = new ArrayList<SequenceItem>();
		closedSeq1.add(new SequenceItem("B", 0));
		FrequentSequence seqAndCount1 = new FrequentSequence(closedSeq1, 2);
		assertTrue(closedSeqs.contains(seqAndCount1));

	}

	@Test
	public void test2() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("A", 1));
		sequences.add(new Sequence("B", 2));
		SequenceDatabase database = new SequenceDatabase(sequences, 1);
		ClosedSequenceMiner miner = new ClosedSequenceMiner(database, 2);
		Set<FrequentSequence> closedSeqs = miner.mineClosedSequences(TaskMonitor.DUMMY);
		assertEquals(1, closedSeqs.size());

		List<SequenceItem> closedSeq1 = new ArrayList<SequenceItem>();
		closedSeq1.add(new SequenceItem("B", 0));
		FrequentSequence seqAndCount1 = new FrequentSequence(closedSeq1, 2);
		assertTrue(closedSeqs.contains(seqAndCount1));

	}

	@Test
	public void test3() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("A", 1));
		sequences.add(new Sequence("B", 2));
		sequences.add(new Sequence("C", 1));
		SequenceDatabase database = new SequenceDatabase(sequences, 1);
		ClosedSequenceMiner miner = new ClosedSequenceMiner(database, 2);
		Set<FrequentSequence> closedSeqs = miner.mineClosedSequences(TaskMonitor.DUMMY);
		assertEquals(1, closedSeqs.size());

		List<SequenceItem> closedSeq1 = new ArrayList<SequenceItem>();
		closedSeq1.add(new SequenceItem("B", 0));
		FrequentSequence seqAndCount1 = new FrequentSequence(closedSeq1, 2);
		assertTrue(closedSeqs.contains(seqAndCount1));

	}

	@Test
	public void test4() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("A", 1));
		sequences.add(new Sequence("B", 2));
		sequences.add(new Sequence("C", 2));
		SequenceDatabase database = new SequenceDatabase(sequences, 1);
		ClosedSequenceMiner miner = new ClosedSequenceMiner(database, 2);
		Set<FrequentSequence> closedSeqs = miner.mineClosedSequences(TaskMonitor.DUMMY);
		assertEquals(2, closedSeqs.size());

		List<SequenceItem> closedSeq1 = new ArrayList<SequenceItem>();
		closedSeq1.add(new SequenceItem("B", 0));
		FrequentSequence seqAndCount1 = new FrequentSequence(closedSeq1, 2);
		assertTrue(closedSeqs.contains(seqAndCount1));

		List<SequenceItem> closedSeq2 = new ArrayList<SequenceItem>();
		closedSeq2.add(new SequenceItem("C", 0));
		FrequentSequence seqAndCount2 = new FrequentSequence(closedSeq2, 2);
		assertTrue(closedSeqs.contains(seqAndCount2));
	}

	@Test
	public void test5() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("ABCD", 2));
		SequenceDatabase database = new SequenceDatabase(sequences, 4);
		ClosedSequenceMiner miner = new ClosedSequenceMiner(database, 2);
		Set<FrequentSequence> closedSeqs = miner.mineClosedSequences(TaskMonitor.DUMMY);
		assertEquals(1, closedSeqs.size());

		List<SequenceItem> closedSeq1 = new ArrayList<SequenceItem>();
		closedSeq1.add(new SequenceItem("A", 0));
		closedSeq1.add(new SequenceItem("B", 1));
		closedSeq1.add(new SequenceItem("C", 2));
		closedSeq1.add(new SequenceItem("D", 3));
		FrequentSequence seqAndCount1 = new FrequentSequence(closedSeq1, 2);
		assertTrue(closedSeqs.contains(seqAndCount1));
	}

	@Test
	public void test6() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("ABCD", 2));
		sequences.add(new Sequence("XBYD", 2));
		sequences.add(new Sequence("AUCV", 2));
		sequences.add(new Sequence("AAAA", 2));
		SequenceDatabase database = new SequenceDatabase(sequences, 4);
		ClosedSequenceMiner miner = new ClosedSequenceMiner(database, 3);
		Set<FrequentSequence> closedSeqs = miner.mineClosedSequences(TaskMonitor.DUMMY);
		assertEquals(3, closedSeqs.size());

		List<SequenceItem> closedSeq1 = new ArrayList<SequenceItem>();
		closedSeq1.add(new SequenceItem("B", 1));
		closedSeq1.add(new SequenceItem("D", 3));
		FrequentSequence seqAndCount1 = new FrequentSequence(closedSeq1, 4);
		assertTrue(closedSeqs.contains(seqAndCount1));

		List<SequenceItem> closedSeq2 = new ArrayList<SequenceItem>();
		closedSeq2.add(new SequenceItem("A", 0));
		FrequentSequence seqAndCount2 = new FrequentSequence(closedSeq2, 6);
		assertTrue(closedSeqs.contains(seqAndCount2));

		List<SequenceItem> closedSeq3 = new ArrayList<SequenceItem>();
		closedSeq3.add(new SequenceItem("A", 0));
		closedSeq3.add(new SequenceItem("C", 2));
		FrequentSequence seqAndCount3 = new FrequentSequence(closedSeq3, 4);
		assertTrue(closedSeqs.contains(seqAndCount3));

	}

	@Test
	public void test7() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("ABCD", 2));
		sequences.add(new Sequence("XBYD", 2));
		sequences.add(new Sequence("AUCV", 2));
		sequences.add(new Sequence("AAAA", 2));
		SequenceDatabase database = new SequenceDatabase(sequences, 4);
		ClosedSequenceMiner miner = new ClosedSequenceMiner(database, 7);
		Set<FrequentSequence> closedSeqs = miner.mineClosedSequences(TaskMonitor.DUMMY);
		assertEquals(0, closedSeqs.size());
	}

	@Test
	public void test8() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("ABCD", 2));
		sequences.add(new Sequence("AABC", 2));
		sequences.add(new Sequence("AAAB", 2));
		sequences.add(new Sequence("AAAA", 2));
		SequenceDatabase database = new SequenceDatabase(sequences, 4);
		ClosedSequenceMiner miner = new ClosedSequenceMiner(database, 3);
		Set<FrequentSequence> closedSeqs = miner.mineClosedSequences(TaskMonitor.DUMMY);
		assertEquals(3, closedSeqs.size());

		List<SequenceItem> closedSeq1 = new ArrayList<SequenceItem>();
		closedSeq1.add(new SequenceItem("A", 0));
		FrequentSequence seqAndCount1 = new FrequentSequence(closedSeq1, 8);
		assertTrue(closedSeqs.contains(seqAndCount1));

		List<SequenceItem> closedSeq2 = new ArrayList<SequenceItem>();
		closedSeq2.add(new SequenceItem("A", 0));
		closedSeq2.add(new SequenceItem("A", 1));
		FrequentSequence seqAndCount2 = new FrequentSequence(closedSeq2, 6);
		assertTrue(closedSeqs.contains(seqAndCount2));

		List<SequenceItem> closedSeq3 = new ArrayList<SequenceItem>();
		closedSeq3.add(new SequenceItem("A", 0));
		closedSeq3.add(new SequenceItem("A", 1));
		closedSeq3.add(new SequenceItem("A", 2));
		FrequentSequence seqAndCount3 = new FrequentSequence(closedSeq3, 4);
		assertTrue(closedSeqs.contains(seqAndCount3));

	}
}
