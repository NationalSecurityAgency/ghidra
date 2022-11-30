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

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class WeakStoreTest extends AbstractGenericTest {
	@Test
	public void testStore() {
		WeakStore<Foo> store = new WeakStore<>();
		store.add(new Foo("AAA"));
		store.add(new Foo("BBB"));
		store.add(new Foo("CCC"));

		assertEquals(3, store.size());

		List<Foo> values = store.getValues();

		assertEquals("AAA", values.get(0).getName());
		assertEquals("BBB", values.get(1).getName());
		assertEquals("CCC", values.get(2).getName());
		values = null;

		waitFor(() -> {
			System.gc();
			return store.size() == 0;
		}, "Weak store values were never garbage collected");
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
