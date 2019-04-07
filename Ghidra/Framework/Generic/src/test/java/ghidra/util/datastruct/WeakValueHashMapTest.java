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

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class WeakValueHashMapTest extends AbstractGenericTest {

	public WeakValueHashMapTest() {
		super();
	}

	@Test
	public void testMap1() throws InterruptedException {
		WeakValueHashMap<Integer, Foo> cache = new WeakValueHashMap<Integer, Foo>();
		cache.put(0, new Foo("AAA"));
		cache.put(1, new Foo("BBB"));
		cache.put(2, new Foo("CCC"));

		assertEquals(3, cache.size());

		assertEquals("AAA", cache.get(0).getName());
		assertEquals("BBB", cache.get(1).getName());
		assertEquals("CCC", cache.get(2).getName());

		for (int i = 0; i < 100; i++) {
			System.gc();
			Thread.sleep(10);
			cache.get(0);
			if (cache.size() == 0) {
				break;
			}
		}
		assertEquals(0, cache.size());

	}

	static class Foo {
		String name;

		Foo(String name) {
			this.name = name;
		}

		String getName() {
			return name;
		}
	}
}
