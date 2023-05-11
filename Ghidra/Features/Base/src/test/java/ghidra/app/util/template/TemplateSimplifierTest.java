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
package ghidra.app.util.template;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.options.ToolOptions;

public class TemplateSimplifierTest extends AbstractGenericTest {

	private TemplateSimplifier simplifier = new TemplateSimplifier();

	@Before
	public void setUp() {
		simplifier.setMinimumTemplateLength(0);
		simplifier.setNestingDepth(0);
		simplifier.setEnabled(true);
	}

	@Test
	public void testSimplifyTemplates() {
		assertEquals("bob<>", simplify("bob<hey>"));
		assertEquals("bob<>", simplify("bob<foo<hey>>"));
		assertEquals("bob<foo<>", simplify("bob<foo<bar>"));
		assertEquals("bob<>", simplify("bob<foo<bar<hey>>>"));
	}

	@Test
	public void testSimplifyTemplatesDepth1() {
		simplifier.setNestingDepth(1);
		assertEquals("bob<hey>", simplify("bob<hey>"));
		assertEquals("bob<foo<>>", simplify("bob<foo<hey>>"));
		assertEquals("bob<foo<bar>", simplify("bob<foo<bar>"));
		assertEquals("bob<foo<>>", simplify("bob<foo<bar<hey>>>"));
	}

	@Test
	public void testSimplifyTemplatesDepth2() {
		simplifier.setNestingDepth(2);
		assertEquals("bob<hey>", simplify("bob<hey>"));
		assertEquals("bob<foo<hey>>", simplify("bob<foo<hey>>"));
		assertEquals("bob<foo<bar>", simplify("bob<foo<bar>"));
		assertEquals("bob<foo<bar<>>>", simplify("bob<foo<bar<hey>>>"));
	}

	@Test
	public void testStripTemplatesWithMaxSize() {
		simplifier.setMaxTemplateLength(10);
		simplifier.setNestingDepth(5);
		assertEquals("bob<abcde...vwxyz>", simplify("bob<abcdefghijklmnopqrstuvwxyz>"));
	}

	@Test
	public void testStripTemplatesWithMaxSizeAndNestedTemplates() {
		simplifier.setMaxTemplateLength(10);
		simplifier.setNestingDepth(5);
		assertEquals("bob<int, ...wxyz>>",
			simplify("bob<int, foo<abcdefghijklmnopqrstuvwxyz>>"));
	}

	@Test
	public void testMinSizeToSimplify() {
		simplifier.setMinimumTemplateLength(5);
		assertEquals("bob<abcde>", simplify("bob<abcde>"));
		assertEquals("bob<>", simplify("bob<abcdef>"));
	}

	@Test
	public void testOptionsGetRegistered() {
		ToolOptions options = new ToolOptions("Listing Fields");
		simplifier = new TemplateSimplifier(options);

		assertTrue(options.isRegistered(TemplateSimplifier.SIMPLIFY_TEMPLATES_OPTION));
		assertTrue(options.isRegistered(TemplateSimplifier.MAX_TEMPLATE_LENGTH_OPTION));
		assertTrue(options.isRegistered(TemplateSimplifier.TEMPLATE_NESTING_DEPTH_OPTION));
		assertTrue(options.isRegistered(TemplateSimplifier.MIN_TEMPLATE_LENGTH_OPTION));
	}

	@Test
	public void testReadsOptions() {
		ToolOptions options = new ToolOptions("Listing Fields");
		options.setBoolean(TemplateSimplifier.SIMPLIFY_TEMPLATES_OPTION, false);
		options.setInt(TemplateSimplifier.MAX_TEMPLATE_LENGTH_OPTION, 33);
		options.setInt(TemplateSimplifier.TEMPLATE_NESTING_DEPTH_OPTION, 3);
		options.setInt(TemplateSimplifier.MIN_TEMPLATE_LENGTH_OPTION, 7);
		simplifier = new TemplateSimplifier(options);

		assertEquals(false, simplifier.isEnabled());
		assertEquals(33, simplifier.getMaxTemplateLength());
		assertEquals(3, simplifier.getNestingDepth());
		assertEquals(7, simplifier.getMinimumTemplateLength());
	}

	private String simplify(String in) {
		return simplifier.simplify(in);
	}

}
