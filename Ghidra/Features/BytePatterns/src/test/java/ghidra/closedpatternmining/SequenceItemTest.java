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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.closedpatternmining.SequenceItem;

public class SequenceItemTest extends AbstractGenericTest {

	@Test
	public void emptySequenceTest() {
		List<SequenceItem> emptyList = new ArrayList<SequenceItem>();
		String dittedString = SequenceItem.getDittedString(emptyList, 0);
		assertEquals("", dittedString);
		dittedString = SequenceItem.getDittedString(emptyList, 3);
		assertEquals("...", dittedString);
	}

	@Test
	public void noDitsTest() {
		List<SequenceItem> testList = new ArrayList<SequenceItem>();
		testList.add(new SequenceItem("A", 0));
		String testString = SequenceItem.getDittedString(testList, 1);
		assertEquals("A", testString);
		testList.add(new SequenceItem("B", 1));
		testString = SequenceItem.getDittedString(testList, 2);
		assertEquals("AB", testString);
	}

	@Test
	public void ditsTest() {
		List<SequenceItem> testList = new ArrayList<SequenceItem>();
		testList.add(new SequenceItem("A", 1));
		String testString = SequenceItem.getDittedString(testList, 2);
		assertEquals(".A", testString);
		testList.add(new SequenceItem("B", 2));
		testString = SequenceItem.getDittedString(testList, 3);
		assertEquals(".AB", testString);
		testList.add(new SequenceItem("C", 5));
		testString = SequenceItem.getDittedString(testList, 6);
		assertEquals(".AB..C", testString);
		testString = SequenceItem.getDittedString(testList, 10);
		assertEquals(".AB..C....", testString);
	}

	@Test(expected = IllegalArgumentException.class)
	public void outOfOrderTest() {
		List<SequenceItem> testList = new ArrayList<SequenceItem>();
		testList.add(new SequenceItem("A", 1));
		testList.add(new SequenceItem("B", 0));
		String testString = SequenceItem.getDittedString(testList, 2);
		System.out.println("Test failed: " + testString);
	}

	@Test
	public void comparisonTests() {
		SequenceItem a1 = new SequenceItem("A", 0);
		SequenceItem a2 = new SequenceItem("A", 0);
		assertEquals(0, a1.compareTo(a1));
		assertEquals(0, a1.compareTo(a2));
		assertEquals(0, a2.compareTo(a1));
		SequenceItem a3 = new SequenceItem("A", 1);
		assertTrue(a1.compareTo(a3) < 0);
		assertEquals(a1.compareTo(a3), -a3.compareTo(a1));
		SequenceItem b1 = new SequenceItem("B", 0);
		assertTrue(a1.compareTo(b1) < 0);
		assertTrue(b1.compareTo(a3) < 0);
	}
}
