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
package generic.stl;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class MapSTLTest extends AbstractGenericTest {

	public MapSTLTest() {
		super();
	}

	@Test
	public void testInsert() {
		MapSTL<Integer, String> map1 = new ComparableMapSTL<>();
		map1.put(0, "zero");
		map1.put(1, "one");
		map1.put(2, "two");
		map1.put(4, "four");

		MapSTL<Integer, String> map2 = new ComparableMapSTL<>();
		map2.put(20, "twenty");
		map2.put(21, "twenty one");
		map2.put(22, "twenty two");
		map2.put(23, "twenty three");

		IteratorSTL<Pair<Integer, String>> begin = map2.begin();
		IteratorSTL<Pair<Integer, String>> end = map2.end();

		// add all
		map1.insert(begin, end);
		assertEquals(8, map1.size());
		assertEquals("zero", map1.get(0));
		assertEquals("one", map1.get(1));
		assertEquals("two", map1.get(2));
		assertEquals("four", map1.get(4));
		assertEquals("twenty", map1.get(20));
		assertEquals("twenty one", map1.get(21));
		assertEquals("twenty two", map1.get(22));
		assertEquals("twenty three", map1.get(23));

		map1 = new ComparableMapSTL<>();
		map1.put(0, "zero");
		map1.put(1, "one");
		map1.put(2, "two");
		map1.put(4, "four");

		begin = map2.begin();
		end = map2.end();

		begin.increment();
		end.decrement();

		map1.insert(begin, end);
		assertEquals(6, map1.size());
		assertEquals("zero", map1.get(0));
		assertEquals("one", map1.get(1));
		assertEquals("two", map1.get(2));
		assertEquals("four", map1.get(4));
		assertEquals("twenty one", map1.get(21));
		assertEquals("twenty two", map1.get(22));
	}
}
