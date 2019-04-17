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
package db;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.NoSuchElementException;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.util.LongIterator;

public class DBFieldMapTest extends AbstractGenericTest {

	private DBFieldMap map;

	public DBFieldMapTest() {

	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		map = new DBFieldMap(StringField.class, 1);
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		if (map != null) {
			map.dispose();
		}
	}

	private void addEntries() {
		map.addEntry(new StringField("f3"), 5);
		map.addEntry(new StringField("f2"), 3);
		map.addEntry(new StringField("f1"), 1);
		map.addEntry(new StringField("f2"), 2);
		map.addEntry(new StringField("f4"), 6);
		map.addEntry(new StringField("f3"), 4);
	}

	@Test
	public void testAddEntry() {

		addEntries();

		assertTrue(map.hasEntry(new StringField("f1"), 1));
		assertTrue(map.hasEntry(new StringField("f2"), 2));
		assertTrue(map.hasEntry(new StringField("f2"), 3));
		assertTrue(map.hasEntry(new StringField("f3"), 4));
		assertTrue(map.hasEntry(new StringField("f3"), 5));
		assertTrue(map.hasEntry(new StringField("f4"), 6));
	}

	@Test
	public void testDeleteEntry() {

		addEntries();

		map.deleteEntry(new StringField("f2"), 2);
		map.deleteEntry(new StringField("f3"), 4);

		assertTrue(map.hasEntry(new StringField("f1"), 1));
		assertTrue(!map.hasEntry(new StringField("f2"), 2));
		assertTrue(map.hasEntry(new StringField("f2"), 3));
		assertTrue(!map.hasEntry(new StringField("f3"), 4));
		assertTrue(map.hasEntry(new StringField("f3"), 5));
		assertTrue(map.hasEntry(new StringField("f4"), 6));
	}

	@Test
	public void testIterator() {

		addEntries();

		LongIterator iter = map.iterator();

		assertEquals(1, iter.next());
		assertEquals(2, iter.next());
		assertEquals(3, iter.next());
		assertEquals(4, iter.next());
		assertEquals(5, iter.next());
		assertEquals(6, iter.next());

		try {
			iter.next();
			Assert.fail();
		}
		catch (NoSuchElementException e) {
			// expected	
		}

		assertEquals(6, iter.previous());
		assertEquals(5, iter.previous());
		assertEquals(4, iter.previous());
		assertEquals(3, iter.previous());
		assertEquals(2, iter.previous());
		assertEquals(1, iter.previous());

		try {
			iter.previous();
			Assert.fail();
		}
		catch (NoSuchElementException e) {
			// expected	
		}

		assertEquals(1, iter.next());
		assertEquals(2, iter.next());
		assertEquals(3, iter.next());
		assertEquals(4, iter.next());

		assertEquals(4, iter.previous());
		assertEquals(3, iter.previous());
		assertEquals(2, iter.previous());
		assertEquals(1, iter.previous());

	}
}
