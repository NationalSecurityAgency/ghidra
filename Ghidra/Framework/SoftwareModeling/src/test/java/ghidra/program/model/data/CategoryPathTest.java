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
/*
 * Created on May 22, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package ghidra.program.model.data;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGTest;

/**
 * {@link CategoryPath} tests.
 */
public class CategoryPathTest extends AbstractGTest {

	@Test
	public void testEscapeStringEmpty() {
		String orig = "";
		String escaped = CategoryPath.escapeString(orig);
		String unescaped = CategoryPath.unescapeString(escaped);
		assertEquals(orig, unescaped);
		assertEquals("", escaped);
	}

	@Test
	public void testEscapeString1() {
		String orig = "/";
		String escaped = CategoryPath.escapeString(orig);
		String unescaped = CategoryPath.unescapeString(escaped);
		assertEquals(orig, unescaped);
		assertEquals("\\/", escaped);
	}

	@Test
	public void testEscapeString2() {
		String orig = "//";
		String escaped = CategoryPath.escapeString(orig);
		String unescaped = CategoryPath.unescapeString(escaped);
		assertEquals(orig, unescaped);
		assertEquals("\\/\\/", escaped);
	}

	@Test
	public void testConstructorRoot1() {
		CategoryPath c = CategoryPath.ROOT;
		assertEquals("/", c.getPath());
		assertEquals("", c.getName());
		assertTrue(c.isRoot());
	}

	@Test
	public void testConstructorRoot2() {
		CategoryPath c = new CategoryPath(null);
		assertEquals("/", c.getPath());
		assertEquals("", c.getName());
		assertTrue(c.isRoot());
	}

	@Test
	public void testConstructorRoot3() {
		CategoryPath c = new CategoryPath("");
		assertEquals("/", c.getPath());
		assertEquals("", c.getName());
		assertTrue(c.isRoot());
	}

	@Test
	public void testConstructorRoot4() {
		CategoryPath c = new CategoryPath("/");
		assertEquals("/", c.getPath());
		assertEquals("", c.getName());
		assertTrue(c.isRoot());
	}

	@Test
	public void testConstructorBasicString1() {
		CategoryPath c = new CategoryPath("/apple");
		assertEquals("/apple", c.getPath());
		assertEquals("apple", c.getName());
	}

	@Test
	public void testConstructorBasicString2() {
		CategoryPath c = new CategoryPath("/apple/pear");
		assertEquals("/apple/pear", c.getPath());
		assertEquals("pear", c.getName());
	}

	@Test
	public void testConstructorParentVarargsSingle() {
		CategoryPath c = new CategoryPath("/apple/pear");
		c = new CategoryPath(c, "mango");
		assertEquals("/apple/pear/mango", c.getPath());
		assertEquals("mango", c.getName());
	}

	@Test
	public void testConstructorParentAndList() {
		CategoryPath parent = new CategoryPath("/universe/earth");
		List<String> list = new ArrayList<>();
		list.add("boy");
		list.add("bad");
		CategoryPath c = new CategoryPath(parent, list);
		assertEquals("/universe/earth/boy/bad", c.getPath());
		assertEquals("bad", c.getName());
	}

	@Test
	public void testConstructorParentAndVarargsArray() {
		CategoryPath parent = new CategoryPath("/apple/peaches");
		CategoryPath c = new CategoryPath(parent, new String[] { "pumpkin", "pie" });
		assertEquals("pie", c.getName());
		c = c.getParent();
		assertEquals("pumpkin", c.getName());
		c = c.getParent();
		assertEquals("peaches", c.getName());
		c = c.getParent();
		assertEquals("apple", c.getName());
		c = c.getParent();
		assertEquals("", c.getName());
		assertTrue(c.isRoot());
	}

	@Test
	public void testConstructorParentAndVarargs() {
		CategoryPath parent = new CategoryPath("/apple/peaches");
		CategoryPath c = new CategoryPath(parent, "pumpkin", "pie");
		assertEquals("pie", c.getName());
		c = c.getParent();
		assertEquals("pumpkin", c.getName());
		c = c.getParent();
		assertEquals("peaches", c.getName());
		c = c.getParent();
		assertEquals("apple", c.getName());
		c = c.getParent();
		assertEquals("", c.getName());
		assertTrue(c.isRoot());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructorBadCtorParam_empty_path_element() {
		new CategoryPath("//");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructorBadCtorParam_empty_path_element_2() {
		new CategoryPath("/apple//bob");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructorBadCtorParam_missing_leading_slash() {
		new CategoryPath("apple");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructorBadCtorParam_bad_trailing_slash() {
		new CategoryPath("/apple/");
	}

	@Test
	public void testGetParent() {
		CategoryPath c = CategoryPath.ROOT;
		assertNull(c.getParent());
		c = new CategoryPath("/aaa/bbb/ccc");
		c = c.getParent();
		assertEquals("/aaa/bbb", c.getPath());
	}

	@Test
	public void testIsAncestorRootRoot() {
		assertTrue(CategoryPath.ROOT.isAncestorOrSelf(CategoryPath.ROOT));
	}

	@Test
	public void testIsAncestorRootApple() {
		CategoryPath apple = new CategoryPath("/apple");
		assertTrue(apple.isAncestorOrSelf(CategoryPath.ROOT));
		assertFalse(CategoryPath.ROOT.isAncestorOrSelf(apple));
	}

	@Test
	public void testIsAncestorAppleSubApple() {
		CategoryPath apple = new CategoryPath("/apple");
		CategoryPath applesub = new CategoryPath("/apple/sub");
		assertTrue(applesub.isAncestorOrSelf(apple));
		assertTrue(applesub.isAncestorOrSelf(applesub));
	}

	@Test
	public void testIsAncestorAppleSubNotApple() {
		CategoryPath applesub = new CategoryPath("/apple/sub");
		CategoryPath notapple = new CategoryPath("/notapple");
		assertFalse(applesub.isAncestorOrSelf(notapple));
	}

	@Test
	public void testIsAncestorAppleSubApp() {
		CategoryPath applesub = new CategoryPath("/apple/sub");
		CategoryPath app = new CategoryPath("/app");
		assertFalse(applesub.isAncestorOrSelf(app));
	}

	@Test
	public void testToArray() {
		CategoryPath path = new CategoryPath("/aaa/bbb/bob");
		String[] names = path.asArray();
		assertEquals("aaa", names[0]);
		assertEquals("bbb", names[1]);
		assertEquals("bob", names[2]);
	}

	@Test
	public void testToList() {
		CategoryPath path = new CategoryPath("/aaa/bbb/bob");
		List<String> names = path.asList();
		assertEquals("aaa", names.get(0));
		assertEquals("bbb", names.get(1));
		assertEquals("bob", names.get(2));
	}

	@Test
	public void testConstructorDelimeterEscape1() {
		CategoryPath path = new CategoryPath("/aaa/bbb/\\/bob");
		List<String> names = path.asList();
		assertEquals("aaa", names.get(0));
		assertEquals("bbb", names.get(1));
		assertEquals("/bob", names.get(2));
		assertEquals("/aaa/bbb/\\/bob", path.getPath());
	}

	@Test
	public void testConstructorDelimeterEscape2() {
		// Should not complain about terminating slash
		CategoryPath path = new CategoryPath("/aaa/bbb/bob\\/");
		List<String> names = path.asList();
		assertEquals("aaa", names.get(0));
		assertEquals("bbb", names.get(1));
		assertEquals("bob/", names.get(2));
		assertEquals("/aaa/bbb/bob\\/", path.getPath());
	}

	@Test
	public void testConstructorDelimeterEscape3() {
		CategoryPath path = new CategoryPath("/\\/aaa/bbb/bob");
		List<String> names = path.asList();
		assertEquals("/aaa", names.get(0));
		assertEquals("bbb", names.get(1));
		assertEquals("bob", names.get(2));
		assertEquals("/\\/aaa/bbb/bob", path.getPath());
	}

	@Test
	public void testConstructorDelimeterEscape4() {
		CategoryPath path = new CategoryPath("/\\/\\/aaa/bbb/bob");
		List<String> names = path.asList();
		assertEquals("//aaa", names.get(0));
		assertEquals("bbb", names.get(1));
		assertEquals("bob", names.get(2));
		assertEquals("/\\/\\/aaa/bbb/bob", path.getPath());
	}

	@Test(expected = IllegalArgumentException.class)
	@SuppressWarnings("unused")
	public void testDelimeterEscapeAtRoot() {
		CategoryPath path = new CategoryPath("\\//aaa/bbb/bob");
	}

	@Test
	public void testConstructorParentVarargsNestedDelimiter1() {
		CategoryPath c = new CategoryPath("/apple/pear");
		// nested delimiter sequence should be ignored on constructor and getName(), but output on
		// getPath().
		c = new CategoryPath(c, "man/go");
		assertEquals("/apple/pear/man\\/go", c.getPath());
		assertEquals("man/go", c.getName());
	}

	@Test
	public void testConstructorParentVarargsNestedEscape1() {
		CategoryPath c = new CategoryPath("/apple/pear");
		// nested escape sequence should be ignored on constructor and getName(), but output on
		// getPath().
		c = new CategoryPath(c, "man\\/go");
		assertEquals("/apple/pear/man\\\\/go", c.getPath());
		assertEquals("man\\/go", c.getName());
	}

}
