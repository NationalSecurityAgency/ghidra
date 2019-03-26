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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class SequenceDatabaseTest extends AbstractGenericTest {

	private SequenceDatabase database;

	@Before
	public void setUp() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("AAAA", 2));
		sequences.add(new Sequence("AAAB", 2));
		sequences.add(new Sequence("AABC", 2));
		sequences.add(new Sequence("AABD", 2));
		sequences.add(new Sequence("ABCE", 2));
		sequences.add(new Sequence("ABCF", 2));
		sequences.add(new Sequence("ABDG", 2));
		sequences.add(new Sequence("ABDI", 2));
		database = new SequenceDatabase(sequences, 4);
	}

	@Test
	public void totalNumSeqsTest() {
		assertEquals(16, database.getTotalNumSeqs());
	}

	@Test
	public void moreThan75PercentTest() {
		Set<FrequentSequenceItem> fi = database.getGloballyFrequentItems(12);
		assertEquals(1, fi.size());
		assertTrue(fi.contains(new FrequentSequenceItem(16, new SequenceItem("A", 0))));
	}

	@Test
	public void moreThan50PercentTest() {
		Set<FrequentSequenceItem> fi = database.getGloballyFrequentItems(8);
		assertEquals(3, fi.size());
		assertTrue(fi.contains(new FrequentSequenceItem(16, new SequenceItem("A", 0))));
		assertTrue(fi.contains(new FrequentSequenceItem(8, new SequenceItem("A", 1))));
		assertTrue(fi.contains(new FrequentSequenceItem(8, new SequenceItem("B", 1))));
	}

	@Test
	public void noFrequentItemsTest() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("A", 1));
		sequences.add(new Sequence("B", 1));
		database = new SequenceDatabase(sequences, 1);
		Set<FrequentSequenceItem> fi = database.getGloballyFrequentItems(12);
		assertEquals(0, fi.size());
	}

}
