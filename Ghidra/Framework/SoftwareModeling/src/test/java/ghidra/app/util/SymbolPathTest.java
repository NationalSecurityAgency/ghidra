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
package ghidra.app.util;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

public class SymbolPathTest {

	@Test
	public void testJustSymbolNameNoPath() {
		SymbolPath symbolPath = new SymbolPath("bob");
		assertEquals("bob", symbolPath.getPath());
		assertEquals("bob", symbolPath.getName());
		assertNull(symbolPath.getParent());
		assertNull(symbolPath.getParentPath());
	}

	@Test
	public void testSymbolPathGivenPathString() {
		SymbolPath symbolPath = new SymbolPath("aaa::bbb::bob");
		assertEquals("aaa::bbb::bob", symbolPath.getPath());
		assertEquals("bob", symbolPath.getName());
		assertEquals(new SymbolPath("aaa::bbb"), symbolPath.getParent());
		assertEquals("aaa::bbb", symbolPath.getParentPath());
	}

	@Test
	public void testArrayConstructorNoData() {
		try {
			new SymbolPath(new String[0]);
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testArrayContructorOneString() {
		SymbolPath symbolPath = new SymbolPath(new String[] { "apple" });
		assertNull(symbolPath.getParent());
		assertEquals("apple", symbolPath.getPath());
		assertEquals("apple", symbolPath.getName());
	}

	@Test
	public void testArrayContructorTwoString() {
		SymbolPath symbolPath = new SymbolPath(new String[] { "orange", "apple" });
		assertEquals(new SymbolPath("orange"), symbolPath.getParent());
		assertEquals("orange", symbolPath.getParentPath());
		assertEquals("orange::apple", symbolPath.getPath());
		assertEquals("apple", symbolPath.getName());
	}

	@Test
	public void testArrayContructorMultipleString() {
		SymbolPath symbolPath = new SymbolPath(new String[] { "orange", "grape", "apple" });
		assertEquals(new SymbolPath("orange::grape"), symbolPath.getParent());
		assertEquals("orange::grape", symbolPath.getParentPath());
		assertEquals("orange::grape::apple", symbolPath.getPath());
		assertEquals("apple", symbolPath.getName());
	}

	@Test
	public void testToArray() {
		SymbolPath symbolPath = new SymbolPath("aaa::bbb::bob");
		String[] names = symbolPath.asArray();
		assertEquals("aaa", names[0]);
		assertEquals("bbb", names[1]);
		assertEquals("bob", names[2]);
	}

	@Test
	public void testToList() {
		SymbolPath symbolPath = new SymbolPath("aaa::bbb::bob");
		List<String> names = symbolPath.asList();
		assertEquals("aaa", names.get(0));
		assertEquals("bbb", names.get(1));
		assertEquals("bob", names.get(2));
	}

	@Test
	public void testCompareTo() {
		SymbolPath symbolPath1 = new SymbolPath("aaa::bbb::bob");
		SymbolPath symbolPath2 = new SymbolPath("aaa");
		SymbolPath symbolPath3 = new SymbolPath("zzz");
		SymbolPath symbolPath4 = new SymbolPath("aaa::bbb::joe");
		SymbolPath symbolPath5 = new SymbolPath("aaa::ccc::joe");

		assertTrue(symbolPath1.compareTo(symbolPath2) > 0);
		assertTrue(symbolPath2.compareTo(symbolPath1) < 0);

		assertTrue(symbolPath1.compareTo(symbolPath1) == 0);

		assertTrue(symbolPath3.compareTo(symbolPath2) > 0);
		assertTrue(symbolPath2.compareTo(symbolPath3) < 0);

		assertTrue(symbolPath4.compareTo(symbolPath1) > 0);
		assertTrue(symbolPath1.compareTo(symbolPath4) < 0);

		assertTrue(symbolPath5.compareTo(symbolPath4) > 0);
		assertTrue(symbolPath4.compareTo(symbolPath5) < 0);

	}
}
