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

import static org.junit.Assert.assertNull;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 * 
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class CategoryPathTest extends AbstractGenericTest {

	public CategoryPathTest() {
		super();
	}

	@Test
	public void testConstructor() {
		CategoryPath c = new CategoryPath(null);
		Assert.assertEquals("/", c.getPath());
		Assert.assertEquals("", c.getName());

		c = new CategoryPath("");
		Assert.assertEquals("/", c.getPath());
		Assert.assertEquals("", c.getName());

		c = new CategoryPath("/");
		Assert.assertEquals("/", c.getPath());
		Assert.assertEquals("", c.getName());

		c = new CategoryPath("/apple");
		Assert.assertEquals("/apple", c.getPath());
		Assert.assertEquals("apple", c.getName());

		c = new CategoryPath("/apple/pear");
		Assert.assertEquals("/apple/pear", c.getPath());
		Assert.assertEquals("pear", c.getName());

		try {
			c = new CategoryPath("//");
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
		}
		try {
			c = new CategoryPath("apple");
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
		}
		try {
			c = new CategoryPath("/apple/");
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
		}
		try {
			c = new CategoryPath("/apple//bob");
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadCtorParam_empty_path_element() {
		new CategoryPath("//");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadCtorParam_empty_path_element_2() {
		new CategoryPath("/apple//bob");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadCtorParam_missing_leading_slash() {
		new CategoryPath("apple");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadCtorParam_bad_trailing_slash() {
		new CategoryPath("/apple/");
	}

	@Test
	public void testOtherConstructor() {
		CategoryPath a = new CategoryPath("/aaa");
		CategoryPath b = new CategoryPath(a, "bbb");
		Assert.assertEquals("/aaa/bbb", b.getPath());
		Assert.assertEquals("bbb", b.getName());
	}

	@Test
	public void testGetParent() {
		CategoryPath c = new CategoryPath(null);
		assertNull(c.getParent());

		c = new CategoryPath("/aaa/bbb/ccc");
		c = c.getParent();
		Assert.assertEquals("/aaa/bbb", c.getPath());
	}

	@Test
	public void testIsAncestor() {

		Assert.assertTrue(CategoryPath.ROOT.isAncestorOrSelf(CategoryPath.ROOT));

		CategoryPath apple = new CategoryPath("/apple");
		Assert.assertTrue(apple.isAncestorOrSelf(CategoryPath.ROOT));
		Assert.assertFalse(CategoryPath.ROOT.isAncestorOrSelf(apple));

		CategoryPath applesub = new CategoryPath("/apple/sub");
		Assert.assertTrue(applesub.isAncestorOrSelf(apple));
		Assert.assertTrue(applesub.isAncestorOrSelf(applesub));

		CategoryPath notapple = new CategoryPath("/notapple");
		Assert.assertFalse(applesub.isAncestorOrSelf(notapple));

		CategoryPath app = new CategoryPath("/app");
		Assert.assertFalse(applesub.isAncestorOrSelf(app));
	}

}
