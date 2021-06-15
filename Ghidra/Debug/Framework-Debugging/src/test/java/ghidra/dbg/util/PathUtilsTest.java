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
package ghidra.dbg.util;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

public class PathUtilsTest {
	@Test
	public void testParseEmpty() {
		assertEquals(List.of(), PathUtils.parse(""));
	}

	@Test
	public void testParseName() {
		assertEquals(List.of("name"), PathUtils.parse("name"));
	}

	@Test
	public void testParseDottedName() {
		assertEquals(List.of("name"), PathUtils.parse(".name"));
	}

	@Test
	public void testParseIndex() {
		assertEquals(List.of("[index]"), PathUtils.parse("[index]"));
	}

	@Test
	public void testParseNameThenIndex() {
		assertEquals(List.of("name", "[index]"), PathUtils.parse("name[index]"));
	}

	@Test
	public void testParseIndexThenName() {
		assertEquals(List.of("[index]", "name"), PathUtils.parse("[index].name"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseErrIndexNoDotName() {
		PathUtils.parse("[index]name");
	}

	@Test
	public void testParseNameThenName() {
		assertEquals(List.of("n1", "n2"), PathUtils.parse("n1.n2"));
	}

	@Test
	public void testParseIndexThenIndex() {
		assertEquals(List.of("[i1]", "[i2]"), PathUtils.parse("[i1][i2]"));
	}

	@Test
	public void testParseIndexWithDot() {
		assertEquals(List.of("[index.more]"), PathUtils.parse("[index.more]"));
	}

	@Test
	public void testParseParenthesizedNameWithDot() {
		assertEquals(List.of("query(e.x==6)"), PathUtils.parse(".query(e.x==6)"));
	}
}
