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
package ghidra.trace.model.target.path;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class KeyPathTest {
	@Test
	public void testParseEmpty() {
		assertEquals(KeyPath.ROOT, KeyPath.parse(""));
	}

	@Test
	public void testParseName() {
		assertEquals(KeyPath.of("name"), KeyPath.parse("name"));
	}

	@Test
	public void testParseDottedName() {
		assertEquals(KeyPath.of("name"), KeyPath.parse(".name"));
	}

	@Test
	public void testParseIndex() {
		assertEquals(KeyPath.of("[index]"), KeyPath.parse("[index]"));
	}

	@Test
	public void testParseNameThenIndex() {
		assertEquals(KeyPath.of("name", "[index]"), KeyPath.parse("name[index]"));
	}

	@Test
	public void testParseIndexThenName() {
		assertEquals(KeyPath.of("[index]", "name"), KeyPath.parse("[index].name"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseErrIndexNoDotName() {
		KeyPath.parse("[index]name");
	}

	@Test
	public void testParseNameThenName() {
		assertEquals(KeyPath.of("n1", "n2"), KeyPath.parse("n1.n2"));
	}

	@Test
	public void testParseIndexThenIndex() {
		assertEquals(KeyPath.of("[i1]", "[i2]"), KeyPath.parse("[i1][i2]"));
	}

	@Test
	public void testParseIndexWithDot() {
		assertEquals(KeyPath.of("[index.more]"), KeyPath.parse("[index.more]"));
	}

	@Test
	public void testParseParenthesizedNameWithDot() {
		assertEquals(KeyPath.of("query(e.x==6)"), KeyPath.parse(".query(e.x==6)"));
	}
}
