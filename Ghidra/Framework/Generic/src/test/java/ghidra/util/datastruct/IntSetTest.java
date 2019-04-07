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
package ghidra.util.datastruct;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class IntSetTest extends AbstractGenericTest {

	public IntSetTest() {
		super();
	}

@Test
    public void testBasic() {
		IntSet set = new IntSet(10);
		set.add(5);
		set.add(7);
		set.add(3);
		set.add(6);
		
		assertEquals(4, set.size());
		
		assertTrue(!set.contains(1));
		assertTrue(!set.contains(2));
		assertTrue( set.contains(3));
		assertTrue(!set.contains(4));
		assertTrue( set.contains(5));
		assertTrue( set.contains(6));
		assertTrue( set.contains(7));
		assertTrue(!set.contains(8));
	
	}
@Test
    public void testInitialized() {
		IntSet set = new IntSet(new int[] {5,6,7,3});

		assertEquals(4, set.size());
		
		assertTrue(!set.contains(1));
		assertTrue(!set.contains(2));
		assertTrue( set.contains(3));
		assertTrue(!set.contains(4));
		assertTrue( set.contains(5));
		assertTrue( set.contains(6));
		assertTrue( set.contains(7));
		assertTrue(!set.contains(8));

	}
	
@Test
    public void testRemove() {
		IntSet set = new IntSet(new int[] {5,6,7,3});

		assertEquals(4, set.size());
		set.remove(6);
		
		assertTrue(!set.contains(1));
		assertTrue(!set.contains(2));
		assertTrue( set.contains(3));
		assertTrue(!set.contains(4));
		assertTrue( set.contains(5));
		assertTrue(!set.contains(6));
		assertTrue( set.contains(7));
		assertTrue(!set.contains(8));

	}
@Test
    public void testRemoveSeveral() {
		IntSet set = new IntSet(new int[] {5,6,7,3});

		assertEquals(4, set.size());
		set.remove(6);
		set.remove(3);
		set.remove(5);
		set.remove(7);
		
		assertEquals(0, set.size());
		assertTrue(set.isEmpty());
		
		assertTrue(!set.contains(1));
		assertTrue(!set.contains(2));
		assertTrue(!set.contains(3));
		assertTrue(!set.contains(4));
		assertTrue(!set.contains(5));
		assertTrue(!set.contains(6));
		assertTrue(!set.contains(7));
		assertTrue(!set.contains(8));

	}	
	
@Test
    public void testRemoveValuesNotInSet() {
		IntSet set = new IntSet(new int[] {5,6,7,3});

		assertEquals(4, set.size());
		set.remove(1);
		set.remove(2);
		set.remove(4);
		set.remove(10);
		
		assertEquals(4, set.size());
		assertTrue(!set.isEmpty());
		
		assertTrue(!set.contains(1));
		assertTrue(!set.contains(2));
		assertTrue( set.contains(3));
		assertTrue(!set.contains(4));
		assertTrue( set.contains(5));
		assertTrue( set.contains(6));
		assertTrue( set.contains(7));
		assertTrue(!set.contains(8));
		
	}
}
