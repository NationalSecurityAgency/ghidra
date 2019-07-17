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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class SequenceTest extends AbstractGenericTest {

	private Sequence testSequence;
	private List<SequenceItem> prefixSequence;
	private int prefixIndex;

	@Before
	public void setUp() {
		testSequence = new Sequence("CAABC", 1);
		prefixSequence = new ArrayList<SequenceItem>();
	}

	@Test
	public void test() {
		//test in paper
		prefixSequence.add(new SequenceItem("A", 2));
		prefixSequence.add(new SequenceItem("B", 3));
		prefixIndex = testSequence.getIndexAfterFirstInstance(prefixSequence);
		assertEquals("CAAB", testSequence.getSequenceAsString().substring(0, prefixIndex));
	}

	@Test
	public void itemDoesntOccurTest() {
		//item doesn't occur test
		prefixSequence.add(new SequenceItem("A", 0));
		prefixIndex = testSequence.getIndexAfterFirstInstance(prefixSequence);
		assertEquals(-1, prefixIndex);
	}

	@Test
	public void prefixTestOne() {
		//prefix with an item that occurs and one that does not
		prefixSequence.add(new SequenceItem("A", 1));
		prefixSequence.add(new SequenceItem("B", 2));
		prefixIndex = testSequence.getIndexAfterFirstInstance(prefixSequence);
		assertEquals(-1, prefixIndex);
	}

	@Test
	public void prefixTestTwo() {
		//prefix with an item that does not occur and one that does 
		prefixSequence.add(new SequenceItem("B", 1));
		prefixSequence.add(new SequenceItem("A", 2));
		prefixIndex = testSequence.getIndexAfterFirstInstance(prefixSequence);
		assertEquals(-1, prefixIndex);
	}

	@Test
	public void prefixTestThree() {
		//entire string as prefix
		prefixSequence.add(new SequenceItem("C", 0));
		prefixSequence.add(new SequenceItem("A", 1));
		prefixSequence.add(new SequenceItem("A", 2));
		prefixSequence.add(new SequenceItem("B", 3));
		prefixSequence.add(new SequenceItem("C", 4));
		prefixIndex = testSequence.getIndexAfterFirstInstance(prefixSequence);
		assertEquals("CAABC".length(), prefixIndex);
	}

	@Test
	public void prefixTestFour() {
		//go out of range
		prefixSequence.add(new SequenceItem("C", 0));
		prefixSequence.add(new SequenceItem("A", 1));
		prefixSequence.add(new SequenceItem("A", 2));
		prefixSequence.add(new SequenceItem("B", 3));
		prefixSequence.add(new SequenceItem("C", 4));
		prefixSequence.add(new SequenceItem("A", 5));
		prefixIndex = testSequence.getIndexAfterFirstInstance(prefixSequence);
		assertEquals(-1, prefixIndex);
	}

}
