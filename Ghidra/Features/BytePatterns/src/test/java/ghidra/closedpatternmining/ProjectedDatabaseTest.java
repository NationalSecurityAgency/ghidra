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

public class ProjectedDatabaseTest extends AbstractGenericTest {

	private SequenceDatabase database;

	@Before
	public void setUp() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("AAAA", 2));
		sequences.add(new Sequence("AAAB", 2));
		sequences.add(new Sequence("AABB", 2));
		sequences.add(new Sequence("ABBB", 2));
		sequences.add(new Sequence("BBBB", 2));
		database = new SequenceDatabase(sequences, 4);
	}

	@Test
	public void projectEmptyStringTest() {
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, new ArrayList<SequenceItem>());
		Set<String> projectedStrings = projDatabase.getProjectedSequencesAsSet();
		assertEquals(10, projDatabase.getSupport());
		assertEquals(5, projectedStrings.size());
		assertTrue(projectedStrings.contains("AAAA"));
		assertTrue(projectedStrings.contains("AAAB"));
		assertTrue(projectedStrings.contains("AABB"));
		assertTrue(projectedStrings.contains("ABBB"));
		assertTrue(projectedStrings.contains("BBBB"));
	}

	@Test
	public void projectSingleCharTest() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		assertEquals(8, projDatabase.getSupport());
		Set<String> projectedStrings = projDatabase.getProjectedSequencesAsSet();
		assertEquals(4, projectedStrings.size());
		assertTrue(projectedStrings.contains("AAA"));
		assertTrue(projectedStrings.contains("AAB"));
		assertTrue(projectedStrings.contains("ABB"));
		assertTrue(projectedStrings.contains("BBB"));
	}

	@Test
	public void projectDoubleCharTest() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		prefixSequence.add(new SequenceItem("A", 1));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		assertEquals(6, projDatabase.getSupport());
		Set<String> projectedStrings = projDatabase.getProjectedSequencesAsSet();
		assertEquals(3, projectedStrings.size());
		assertTrue(projectedStrings.contains("AA"));
		assertTrue(projectedStrings.contains("AB"));
		assertTrue(projectedStrings.contains("BB"));
	}

	@Test
	public void projectTwiceTest1() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		SequenceItem extendingItem = new SequenceItem("A", 1);
		ProjectedDatabase secondProjection = new ProjectedDatabase(projDatabase, extendingItem);
		assertEquals(6, secondProjection.getSupport());
		Set<String> projectedStrings = secondProjection.getProjectedSequencesAsSet();
		assertEquals(3, projectedStrings.size());
		assertTrue(projectedStrings.contains("AA"));
		assertTrue(projectedStrings.contains("AB"));
		assertTrue(projectedStrings.contains("BB"));
	}

	@Test
	public void projectTwiceTest2() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		SequenceItem extendingItem = new SequenceItem("A", 2);
		ProjectedDatabase secondProjection = new ProjectedDatabase(projDatabase, extendingItem);
		assertEquals(4, secondProjection.getSupport());
		Set<String> projectedStrings = secondProjection.getProjectedSequencesAsSet();
		assertEquals(2, projectedStrings.size());
		assertTrue(projectedStrings.contains("A"));
		assertTrue(projectedStrings.contains("B"));
	}

	@Test
	public void projectEntireTest() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		prefixSequence.add(new SequenceItem("A", 1));
		prefixSequence.add(new SequenceItem("A", 2));
		prefixSequence.add(new SequenceItem("A", 3));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		assertEquals(2, projDatabase.getSupport());
		Set<String> projectedStrings = projDatabase.getProjectedSequencesAsSet();
		assertEquals(1, projectedStrings.size());
	}

	@Test
	public void projectNonOccuringCharTest() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("C", 0));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		assertEquals(0, projDatabase.getSupport());
		Set<String> projectedStrings = projDatabase.getProjectedSequencesAsSet();
		assertEquals(0, projectedStrings.size());
	}

	@Test
	public void testLocallyFrequentItemsBasic() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		prefixSequence.add(new SequenceItem("A", 1));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> globallyFrequent = database.getGloballyFrequentItems(4);
		Set<FrequentSequenceItem> locallyFrequent =
			projDatabase.getLocallyFrequentItems(globallyFrequent, 4);
		assertEquals(2, locallyFrequent.size());
		assertTrue(locallyFrequent.contains(new FrequentSequenceItem(4, new SequenceItem("B", 3))));
		assertTrue(locallyFrequent.contains(new FrequentSequenceItem(4, new SequenceItem("A", 2))));
	}

	@Test
	public void testLocallyFrequentItemsEmptyProjectedDatabase() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		prefixSequence.add(new SequenceItem("A", 1));
		prefixSequence.add(new SequenceItem("A", 2));
		prefixSequence.add(new SequenceItem("A", 3));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> globallyFrequent = database.getGloballyFrequentItems(4);
		Set<FrequentSequenceItem> locallyFrequent =
			projDatabase.getLocallyFrequentItems(globallyFrequent, 4);
		assertEquals(0, locallyFrequent.size());
	}

	@Test
	public void testLocallyFrequentItemsDits() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> globallyFrequent = database.getGloballyFrequentItems(6);
		Set<FrequentSequenceItem> locallyFrequent =
			projDatabase.getLocallyFrequentItems(globallyFrequent, 6);
		assertEquals(2, locallyFrequent.size());
		assertTrue(locallyFrequent.contains(new FrequentSequenceItem(6, new SequenceItem("A", 1))));
		assertTrue(locallyFrequent.contains(new FrequentSequenceItem(6, new SequenceItem("B", 3))));
	}

	@Test
	public void testLocallyFrequentItemsNoFrequentItems() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		prefixSequence.add(new SequenceItem("A", 1));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> globallyFrequent = database.getGloballyFrequentItems(6);
		Set<FrequentSequenceItem> locallyFrequent =
			projDatabase.getLocallyFrequentItems(globallyFrequent, 6);
		assertEquals(0, locallyFrequent.size());
	}

	@Test
	public void noForwardExtensionItemsTest() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> globallyFrequent = database.getGloballyFrequentItems(6);
		Set<FrequentSequenceItem> locallyFrequent =
			projDatabase.getLocallyFrequentItems(globallyFrequent, 6);
		Set<FrequentSequenceItem> extensionItems = projDatabase.getForwardExtensionItems(locallyFrequent);
		assertEquals(0, extensionItems.size());
	}

	@Test
	public void testForwardExtensionItems() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("CDAAAA", 2));
		sequences.add(new Sequence("CDAAAB", 2));
		sequences.add(new Sequence("CDAABB", 2));
		sequences.add(new Sequence("CDABBB", 2));
		sequences.add(new Sequence("CDBBBB", 2));
		database = new SequenceDatabase(sequences, 6);
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("C", 0));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> globallyFrequent = database.getGloballyFrequentItems(6);
		Set<FrequentSequenceItem> locallyFrequent =
			projDatabase.getLocallyFrequentItems(globallyFrequent, 6);
		Set<FrequentSequenceItem> extensionItems = projDatabase.getForwardExtensionItems(locallyFrequent);
		assertEquals(1, extensionItems.size());
		assertTrue(extensionItems.contains(new FrequentSequenceItem(10, new SequenceItem("D", 1))));
	}

	@Test
	//no backward extension items because there are no ditted spaces
	public void noBackwardExtensionItemsTest1() {
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 0));
		prefixSequence.add(new SequenceItem("A", 1));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> backwardExtensionItems = projDatabase.getBackwardExtensionItems();
		assertEquals(0, backwardExtensionItems.size());
	}

	@Test
	//no backward extension items even though there are ditted spaces
	public void noBackwardExtensionItemsTest2() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("CDAAAA", 2));
		sequences.add(new Sequence("CDAAAB", 2));
		sequences.add(new Sequence("CEAABB", 2));
		sequences.add(new Sequence("CDABBB", 2));
		sequences.add(new Sequence("CDABBB", 2));
		database = new SequenceDatabase(sequences, 6);
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("C", 0));
		prefixSequence.add(new SequenceItem("A", 2));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> backwardExtensionItems = projDatabase.getBackwardExtensionItems();
		assertEquals(0, backwardExtensionItems.size());
	}

	@Test
	public void simpleBackwardExtensionItemTest1() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("AA", 2));
		database = new SequenceDatabase(sequences, 2);
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 1));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> backwardExtensionItems = projDatabase.getBackwardExtensionItems();
		assertEquals(1, backwardExtensionItems.size());
	}

	@Test
	public void simpleBackwardExtensionItemTest2() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("AAA", 2));
		database = new SequenceDatabase(sequences, 3);
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("A", 1));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> backwardExtensionItems = projDatabase.getBackwardExtensionItems();
		assertEquals(1, backwardExtensionItems.size());
	}

	@Test
	public void oneBackwardExtensionItemTest1() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("CDAAAA", 2));
		sequences.add(new Sequence("CDAAAB", 2));
		sequences.add(new Sequence("CDAABB", 2));
		sequences.add(new Sequence("CDABBB", 2));
		sequences.add(new Sequence("CDABBE", 2));
		database = new SequenceDatabase(sequences, 6);
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("C", 0));
		prefixSequence.add(new SequenceItem("A", 2));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> backwardExtensionItems = projDatabase.getBackwardExtensionItems();
		assertEquals(1, backwardExtensionItems.size());
		assertTrue(backwardExtensionItems.contains(new FrequentSequenceItem(10, new SequenceItem("D", 1))));
	}

	@Test
	public void oneBackwardExtensionItemTest2() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("CAAFBA", 2));
		sequences.add(new Sequence("CBAGBB", 2));
		sequences.add(new Sequence("CCAHBB", 2));
		sequences.add(new Sequence("CDAIBB", 2));
		sequences.add(new Sequence("CEAJBB", 2));
		database = new SequenceDatabase(sequences, 6);
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("C", 0));
		prefixSequence.add(new SequenceItem("B", 4));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> backwardExtensionItems = projDatabase.getBackwardExtensionItems();
		assertEquals(1, backwardExtensionItems.size());
		assertTrue(backwardExtensionItems.contains(new FrequentSequenceItem(10, new SequenceItem("A", 2))));
	}

	@Test
	public void twoBackwardExtensionItemsTest1() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("CABDBA", 2));
		sequences.add(new Sequence("CABDBB", 2));
		sequences.add(new Sequence("CABDBI", 2));
		sequences.add(new Sequence("CABDBJ", 2));
		sequences.add(new Sequence("CEAJBB", 2));
		database = new SequenceDatabase(sequences, 6);
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("C", 0));
		prefixSequence.add(new SequenceItem("D", 3));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> backwardExtensionItems = projDatabase.getBackwardExtensionItems();
		assertEquals(2, backwardExtensionItems.size());
		assertTrue(backwardExtensionItems.contains(new FrequentSequenceItem(8, new SequenceItem("A", 1))));
		assertTrue(backwardExtensionItems.contains(new FrequentSequenceItem(8, new SequenceItem("B", 2))));
	}

	@Test
	public void threeBackwardExtensionItemsTest3() {
		List<Sequence> sequences = new ArrayList<>();
		sequences.add(new Sequence("CABDBNGA", 2));
		sequences.add(new Sequence("CAADBNGB", 2));
		sequences.add(new Sequence("CAADXNGC", 2));
		sequences.add(new Sequence("CABDBNGD", 2));
		sequences.add(new Sequence("CEAJBBHE", 2));
		database = new SequenceDatabase(sequences, 8);
		List<SequenceItem> prefixSequence = new ArrayList<SequenceItem>();
		prefixSequence.add(new SequenceItem("C", 0));
		prefixSequence.add(new SequenceItem("G", 6));
		ProjectedDatabase projDatabase = new ProjectedDatabase(database, prefixSequence);
		Set<FrequentSequenceItem> backwardExtensionItems = projDatabase.getBackwardExtensionItems();
		assertEquals(3, backwardExtensionItems.size());
		assertTrue(backwardExtensionItems.contains(new FrequentSequenceItem(8, new SequenceItem("A", 1))));
		assertTrue(backwardExtensionItems.contains(new FrequentSequenceItem(8, new SequenceItem("D", 3))));
		assertTrue(backwardExtensionItems.contains(new FrequentSequenceItem(8, new SequenceItem("N", 5))));
	}

}
