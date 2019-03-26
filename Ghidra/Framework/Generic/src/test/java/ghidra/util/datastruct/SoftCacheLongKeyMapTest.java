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
import static org.junit.Assert.assertNull;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class SoftCacheLongKeyMapTest extends AbstractGenericTest {
	SoftCacheLongKeyMap cache;

	/**
	 * 
	 */
	public SoftCacheLongKeyMapTest() {
		super();
	}

	@Test
    public void testMap() {
		cache = new SoftCacheLongKeyMap(20);
		cache.put(0, "aaa");
		cache.put(1, "bbb");
		cache.put(2, "ccc");

		assertEquals(3, cache.size());
		assertEquals("aaa", cache.get(0));
		assertEquals("bbb", cache.get(1));
		assertEquals("ccc", cache.get(2));
	}

	@Test
    public void testlru() {
		cache = new SoftCacheLongKeyMap(10);
		cache.put(0, "aaa");
		cache.put(1, "bbb");
		cache.put(2, "ccc");
		cache.put(3, "ddd");
		cache.put(4, "eee");
		cache.put(5, "fff");
		cache.put(6, "ggg");
		cache.put(7, "hhh");
		cache.put(8, "iii");
		cache.put(9, "jjj");

		assertEquals(10, cache.size());
		cache.put(10, "kkk");
		assertEquals(10, cache.size());
		assertNull(cache.get(0));

	}

	@Test
    public void testlru2() {
		cache = new SoftCacheLongKeyMap(10);
		cache.put(0, "aaa");
		cache.put(1, "bbb");
		cache.put(2, "ccc");
		cache.put(3, "ddd");
		cache.put(4, "eee");
		cache.put(5, "fff");
		cache.put(6, "ggg");
		cache.put(7, "hhh");
		cache.put(8, "iii");
		cache.put(9, "jjj");
		cache.get(0);
		assertEquals(10, cache.size());
		cache.put(10, "kkk");
		assertEquals(10, cache.size());
		assertEquals("aaa", cache.get(0));
		assertNull(cache.get(1));
	}

	@Test
    public void testRemove() {
		cache = new SoftCacheLongKeyMap(10);
		cache.put(0, "aaa");
		cache.put(1, "bbb");
		cache.put(2, "ccc");
		cache.put(3, "ddd");
		cache.remove(1);
		cache.remove(0);
		cache.remove(3);
		cache.remove(2);
		assertEquals(0, cache.size());
		cache.put(5, "zzz");
		assertEquals(1, cache.size());
		cache.remove(5);
		assertEquals(0, cache.size());

	}
}
