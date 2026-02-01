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
package ghidra.app.util.bin.format.golang.rtti;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.format.golang.GoVer;
import ghidra.app.util.bin.format.golang.GoVerRange;
import ghidra.app.util.bin.format.golang.GoVerSet;

public class GoVerTest {

	@Test
	public void testParseVer() {
		assertEquals(1, GoVer.parse("1.2").getMajor());
		assertEquals(2, GoVer.parse("1.2").getMinor());
		assertEquals(0, GoVer.parse("1.2.0").getPatch());
		assertEquals(3, GoVer.parse("1.2.3").getPatch());
	}
	
	@Test
	public void testParseRangeCompare() {
		GoVerRange range = GoVerRange.parse("1.1-1.55");
		assertTrue(range.contains(GoVer.parse("1.2.55")));
		assertTrue(range.contains(GoVer.parse("1.55")));
		assertTrue(range.contains(GoVer.parse("1.55.1")));
		assertFalse(range.contains(GoVer.parse("1.56")));
	}

	@Test
	public void testParseRange() {
		GoVerRange range = GoVerRange.parse("1.1-1.55");
		assertEquals("1.1", range.start().toString());
		assertEquals("1.55", range.end().toString());

		range = GoVerRange.parse("1.1-");
		assertEquals("1.1", range.start().toString());
		assertTrue(range.end().isWildcard());

		range = GoVerRange.parse("-1.55");
		assertTrue(range.start().isWildcard());
		assertEquals("1.55", range.end().toString());

		range = GoVerRange.parse("1.55");
		assertEquals("1.55", range.start().toString());
		assertEquals("1.55", range.end().toString());
		assertTrue(range.contains(GoVer.parse("1.55")));
	}

	@Test
	public void testParseRangeBad() {
		GoVerRange range = GoVerRange.parse("1.1-xx");
		assertTrue(range.isEmpty());

		range = GoVerRange.parse("xx");
		assertTrue(range.isEmpty());

		range = GoVerRange.parse("-");
		assertTrue(range.isEmpty());
	}

	@Test
	public void testParseRangeEmtpy() {
		GoVerRange range = GoVerRange.parse("");
		assertTrue(range.isEmpty());
	}

	@Test
	public void testParseSetAll() throws IOException {
		assertTrue(GoVerSet.parse("all").contains(GoVer.parse("1.1")));
		assertTrue(GoVerSet.parse("all").contains(GoVer.parse("99.44")));
	}

	@Test
	public void testParseSetEmpty() throws IOException {
		assertTrue(GoVerSet.parse("").isEmpty());
	}

	@Test
	public void testParseSetBad() throws IOException {
		assertTrue(GoVerSet.parse("-").isEmpty());
	}

	@Test
	public void testParseSetMultirange() throws IOException {
		GoVerSet vers = GoVerSet.parse("1.2-1.22.3,1.55,1.77.0");
		
		assertFalse(vers.contains(GoVer.parse("1.1")));
		
		assertTrue(vers.contains(GoVer.parse("1.2")));
		assertTrue(vers.contains(GoVer.parse("1.22.3")));
		assertFalse(vers.contains(GoVer.parse("1.22.4")));
		
		assertTrue(vers.contains(GoVer.parse("1.55.0")));
		assertTrue(vers.contains(GoVer.parse("1.55.1")));
		
		assertTrue(vers.contains(GoVer.parse("1.77.0")));
		assertFalse(vers.contains(GoVer.parse("1.77.1")));
	}
	
	@Test
	public void testParseSetWildcardRanges() throws IOException {
		GoVerSet vers = GoVerSet.parse("1.2-");
		assertFalse(vers.contains(GoVer.parse("1.1")));
		assertTrue(vers.contains(GoVer.parse("1.2")));
		assertTrue(vers.contains(GoVer.parse("1.99")));
		assertTrue(vers.contains(GoVer.parse("99.99")));
		
		vers = GoVerSet.parse("-1.2,1.5,1.9-");
		assertTrue(vers.contains(GoVer.parse("1.1")));
		assertTrue(vers.contains(GoVer.parse("1.2")));
		assertFalse(vers.contains(GoVer.parse("1.3")));
		assertTrue(vers.contains(GoVer.parse("1.5.1")));
		assertFalse(vers.contains(GoVer.parse("1.8")));
		assertTrue(vers.contains(GoVer.parse("1.9")));
		assertTrue(vers.contains(GoVer.parse("99.99")));
		
		vers = GoVerSet.parse("-1.2.1");
		assertTrue(vers.contains(GoVer.parse("1.1")));
		assertTrue(vers.contains(GoVer.parse("1.2.0")));
		assertTrue(vers.contains(GoVer.parse("1.2.1")));
		assertFalse(vers.contains(GoVer.parse("1.2.3")));
		
		assertTrue(vers.contains(GoVer.parse("1.2")));
	}
	
	@Test(expected = IOException.class)
	public void testParseSetWildcardRangesBadLeading() throws IOException {
		GoVerSet.parse("1.2-1.3,-1.5");
	}
	
	@Test(expected = IOException.class)
	public void testParseSetWildcardRangesBadTrailing() throws IOException {
		GoVerSet.parse("1.2-1.3,1.5-,1.8");
	}
}
