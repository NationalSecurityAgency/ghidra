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
package ghidra.app.util.navigation;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.model.StubProgram;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class SymbolMatcherTest {

	private SymbolMatcher matcher;

	@Test
	public void testNoNamespaceQueryCaseSensitive() {
		matcher = new SymbolMatcher("bob", true);

		assertMatches(matcher, "bob");
		assertMatches(matcher, "a::bob");
		assertMatches(matcher, "a::b::bob");
		assertMatches(matcher, "a::b::c::bob");

		assertNotMatches(matcher, "Bob");
		assertNotMatches(matcher, "a::Bob");
		assertNotMatches(matcher, "a::b::Bob");
		assertNotMatches(matcher, "a::b::bob:joe");

	}

	@Test
	public void testNoNamespaceQueryCaseInsenstive() {
		matcher = new SymbolMatcher("bob", false);

		assertMatches(matcher, "bob");
		assertMatches(matcher, "a::bob");
		assertMatches(matcher, "a::b::bob");
		assertMatches(matcher, "a::b::c::bob");
		assertMatches(matcher, "Bob");
		assertMatches(matcher, "a::Bob");
		assertMatches(matcher, "a::b::Bob");
		assertMatches(matcher, "a::b::c::Bob");
	}

	@Test
	public void testNoNamespaceQueryWildCardsCaseSensitive() {
		matcher = new SymbolMatcher("bo*", true);

		assertMatches(matcher, "bob");
		assertMatches(matcher, "a::bob");
		assertMatches(matcher, "a::b::bob");
		assertMatches(matcher, "a::b::c::bob");

		assertNotMatches(matcher, "Bob");
		assertNotMatches(matcher, "a::Bob");
		assertNotMatches(matcher, "a::b::Bob");
		assertNotMatches(matcher, "a::b::c::Bob");
	}

	@Test
	public void testNoNamespaceQueryWildCardsCaseInsensitive() {
		matcher = new SymbolMatcher("bo*", false);
		assertMatches(matcher, "bob");
		assertMatches(matcher, "a::bob");
		assertMatches(matcher, "a::b::bob");
		assertMatches(matcher, "a::b::c::bob");

		assertMatches(matcher, "Bob");
		assertMatches(matcher, "a::Bob");
		assertMatches(matcher, "a::b::Bob");
		assertMatches(matcher, "a::b::c::Bob");
	}

	@Test
	public void testNoNamespaceQuerySingleCharWildCardsCaseSensitive() {
		matcher = new SymbolMatcher("b?b", true);

		assertMatches(matcher, "bob");
		assertMatches(matcher, "a::bob");
		assertMatches(matcher, "a::b::bob");
		assertMatches(matcher, "a::b::c::bob");

		assertNotMatches(matcher, "Bob");
		assertNotMatches(matcher, "a::Bob");
		assertNotMatches(matcher, "a::b::Bob");
		assertNotMatches(matcher, "a::b::c::Bob");
	}

	@Test
	public void testNoNamespaceQuerySingleCharWildCardsCaseInsensitive() {
		matcher = new SymbolMatcher("b?b", false);

		assertMatches(matcher, "bob");
		assertMatches(matcher, "a::bob");
		assertMatches(matcher, "a::b::bob");
		assertMatches(matcher, "a::b::c::bob");

		assertMatches(matcher, "Bob");
		assertMatches(matcher, "a::Bob");
		assertMatches(matcher, "a::b::Bob");
		assertMatches(matcher, "a::b::c::Bob");
	}

	@Test
	public void testWithNamespace() {
		matcher = new SymbolMatcher("apple::bob", false);

		assertMatches(matcher, "apple::bob");
		assertMatches(matcher, "x::apple::bob");
		assertMatches(matcher, "x::y::apple::bob");

		assertNotMatches(matcher, "bob");
		assertNotMatches(matcher, "Bob");
		assertNotMatches(matcher, "dog::Bob");
		assertNotMatches(matcher, "apple::x::Bob");
	}

	@Test
	public void testWithNamespaceTwoLevels() {
		matcher = new SymbolMatcher("apple::car::bob", false);

		assertMatches(matcher, "apple::car::bob");
		assertMatches(matcher, "x::apple::car::bob");
		assertMatches(matcher, "x::y::apple::car::bob");

		assertNotMatches(matcher, "bob");
		assertNotMatches(matcher, "apple::bob");
		assertNotMatches(matcher, "apple::x::bob");
	}

	@Test
	public void testWithFullWildNamespace() {
		matcher = new SymbolMatcher("*::bob", false);

		assertMatches(matcher, "apple::bob");
		assertMatches(matcher, "dog::bob");
		assertMatches(matcher, "x::y::bob");

		assertNotMatches(matcher, "bob");
		assertNotMatches(matcher, "joe");
		assertNotMatches(matcher, "bo");
		assertNotMatches(matcher, "bobby");
		assertNotMatches(matcher, "x::boby");
	}

	@Test
	public void testWithPartialWildNamespace() {
		matcher = new SymbolMatcher("*a*::bob", false);

		assertMatches(matcher, "apple::bob");
		assertMatches(matcher, "banana::bob");
		assertMatches(matcher, "x::car::bob");

		assertNotMatches(matcher, "bob");
		assertNotMatches(matcher, "apple::bo");
		assertNotMatches(matcher, "apple::x::bob");
	}

	@Test
	public void testWithWildNamespaceAbsolutePath() {
		matcher = new SymbolMatcher("::*::bob", false);

		assertMatches(matcher, "apple::bob");
		assertMatches(matcher, "x::bob");

		assertNotMatches(matcher, "bob");
		assertNotMatches(matcher, "x::apple::bo");
		assertNotMatches(matcher, "apple::x::bob");

	}

	@Test
	public void testEmptyPath() {
		matcher = new SymbolMatcher("", false);

		assertNotMatches(matcher, "bob");
		assertNotMatches(matcher, "a:b");
	}

	@Test
	public void testPathGlobbing() {
		matcher = new SymbolMatcher("Apple::**::dog", false);

		assertMatches(matcher, "Apple::dog");
		assertMatches(matcher, "Apple::x::dog");
		assertMatches(matcher, "Apple::x::y::dog");
		assertMatches(matcher, "Apple::x::Apple::dog");
		assertMatches(matcher, "a::b::Apple::x::y::dog");

		assertNotMatches(matcher, "dog");
		assertNotMatches(matcher, "x::dog");
		assertNotMatches(matcher, "Apple::x::doggy");
		assertNotMatches(matcher, "Applebob::x::dog");

	}

	@Test
	public void testMulitiplePathGlobbing() {
		matcher = new SymbolMatcher("Apple::**::cat::**::dog", false);

		assertMatches(matcher, "Apple::cat::dog");
		assertMatches(matcher, "Apple::x::cat::dog");
		assertMatches(matcher, "Apple::x::cat::y::dog");
		assertMatches(matcher, "Apple::cat::x::Apple::dog");
		assertMatches(matcher, "Apple::x::Apple::cat::dog");
		assertMatches(matcher, "a::b::Apple::x::cat::dog");

		assertNotMatches(matcher, "dog");
		assertNotMatches(matcher, "Apple::dog");
		assertNotMatches(matcher, "cat::dog");
	}

	@Test
	public void testPathGlobbingAtEnd() {
		matcher = new SymbolMatcher("Apple::**", false);

		assertMatches(matcher, "Apple::dog");
		assertMatches(matcher, "Apple::cat::dog");
		assertMatches(matcher, "Apple::x::cat::dog");
		assertMatches(matcher, "Apple::x::cat::y::dog");
		assertMatches(matcher, "Apple::cat::x::Apple::dog");
		assertMatches(matcher, "Apple::x::Apple::cat::dog");
		assertMatches(matcher, "a::b::Apple::x::cat::dog");

		assertNotMatches(matcher, "dog");
		assertNotMatches(matcher, "Apple");
	}

	@Test
	public void testPathGlobbingAtStart() {
		// note that this really should be no different than the query "dog", but it should still
		// work if you put the "**::" at the beginning
		matcher = new SymbolMatcher("**::dog", false);

		assertMatches(matcher, "dog");
		assertMatches(matcher, "Apple::dog");
		assertMatches(matcher, "Apple::cat::dog");
		assertMatches(matcher, "Apple::x::cat::dog");
		assertMatches(matcher, "Apple::x::cat::y::dog");
		assertMatches(matcher, "Apple::cat::x::Apple::dog");
		assertMatches(matcher, "Apple::x::Apple::cat::dog");
		assertMatches(matcher, "a::b::Apple::x::cat::dog");

		assertNotMatches(matcher, "Apple");
	}

	@Test
	public void testBadDoubleStartActsLikeSingleStar() {
		// Should behave as if the query was "Apple*::dog because we only support "**" when 
		// it is completely surrounded by delimiters. In this case the ** is treated as if
		// the user made a mistake and meant to input just a single *.
		matcher = new SymbolMatcher("Apple**::dog", false);

		assertMatches(matcher, "Apple::x::Apple::dog");
		assertMatches(matcher, "Apple::dog");
		assertMatches(matcher, "Applebob::dog");

		assertNotMatches(matcher, "Apple::x::dog");
		assertNotMatches(matcher, "Apple::x::y::dog");
		assertNotMatches(matcher, "a::b::Apple::x::y::dog");

		assertNotMatches(matcher, "dog");
		assertNotMatches(matcher, "x::dog");
		assertNotMatches(matcher, "Apple::x::doggy");

	}

	@Test
	public void testPathGlobbingWithNameGlobbing() {
		matcher = new SymbolMatcher("Ap*le::**::do*", false);

		assertMatches(matcher, "Apple::dog");
		assertMatches(matcher, "Apple::x::dog");
		assertMatches(matcher, "Apple::x::y::dog");
		assertMatches(matcher, "Apple::x::Apple::dog");
		assertMatches(matcher, "a::b::Apple::x::y::dog");
		assertMatches(matcher, "Apple::x::doggy");

		assertNotMatches(matcher, "dog");
		assertNotMatches(matcher, "x::dog");

	}

	@Test
	public void testNameGlobingAfterDotInName() {
		// We don't support the regex ".*" directly from user input. If the user
		// enters "*.*::bob", the "." should only match the literal '.' character.
		matcher = new SymbolMatcher("*.*::bob", false);

		assertMatches(matcher, "a.a::bob");
		assertNotMatches(matcher, "a.a::c::bob");
	}

	@Test
	public void testNameGlobingExcessStars() {
		// 3 stars is assumed to be a mistake and will be treated as though it were a single *
		matcher = new SymbolMatcher("a***b::bob", false);

		assertMatches(matcher, "axxxb::bob");
		assertNotMatches(matcher, "a::b::bob");

		// In this context, where the extended *s are enclosed in delimiters, we assume the user
		// meant **
		matcher = new SymbolMatcher("a::***::bob", false);

		assertMatches(matcher, "a::b::bob");
		assertNotMatches(matcher, "axxxb::bob");

		matcher = new SymbolMatcher("a****b::bob", false);

		assertMatches(matcher, "axxxb::bob");
		assertNotMatches(matcher, "a::b::bob");

		matcher = new SymbolMatcher("a::****::bob", false);

		assertMatches(matcher, "a::b::bob");
		assertNotMatches(matcher, "axxxb::bob");

		matcher = new SymbolMatcher("bob*****", false);
		assertMatches(matcher, "bobby");

	}

	@Test
	public void testBlockNameMatches() {
		// all of our symbols are stubbed to be in the ".text" block
		matcher = new SymbolMatcher(".text::bob", false);

		// since ".text is the block name for all of our symbols in this test, any
		// "bob" symbol, regardless of its namespace should match the query ".text::bob"
		assertMatches(matcher, "bob");
		assertMatches(matcher, "aaa::bob");
		assertMatches(matcher, "x::y::z::bob");
	}

	@Test
	public void testBlockNameMatchesDontSupportWildsInBlockName() {
		// All of our symbols are stubbed to be in the ".text" block. Legacy code allowed
		// users to search for symbols in memory blocks int the form <block name>::<symbol name>.
		// We still support that, but didn't add wildcard support as that might be even more
		// confusing that it already is.

		matcher = new SymbolMatcher(".t*xt::bob", false);
		assertNotMatches(matcher, "bob");
		assertNotMatches(matcher, "aaa::bob");
		assertNotMatches(matcher, "x::y::z::bob");

		matcher = new SymbolMatcher(".t?xt::bob", false);
		assertNotMatches(matcher, "bob");
		assertNotMatches(matcher, "aaa::bob");
		assertNotMatches(matcher, "x::y::z::bob");
	}

	@Test
	public void testBlockNameMatchesSupportWildsInSymbolName() {
		// all of our symbols are stubbed to be in the ".text" block
		matcher = new SymbolMatcher(".text::bob*", false);

		assertMatches(matcher, "bob");
		assertMatches(matcher, "bobx");
		assertMatches(matcher, "bobyy");
		assertMatches(matcher, "aaa::bobz");
		assertMatches(matcher, "x::y::z::bobby");
	}

	@Test
	public void testGetSymbolName() {
		matcher = new SymbolMatcher("a::b::c", false);
		assertEquals("c", matcher.getSymbolName());
	}

	@Test
	public void testHasFullySpecifiedName() {
		matcher = new SymbolMatcher("a::b::c", false);
		assertFalse(matcher.hasFullySpecifiedName());

		matcher = new SymbolMatcher("a::b::c", true);
		assertTrue(matcher.hasFullySpecifiedName());

		matcher = new SymbolMatcher("a::b::c*", true);
		assertFalse(matcher.hasFullySpecifiedName());

		matcher = new SymbolMatcher("a::b*::c", true);
		assertTrue(matcher.hasFullySpecifiedName());

	}

	@Test
	public void testHasWildcardsInSymbolName() {
		// This is testing the SymbolMatcher.hasWidCardsInSymbolName() method, which is used
		// to optimize symbol searching when symbol names don't have wildcard characters.

		matcher = new SymbolMatcher("a::b::c", false);
		assertFalse(matcher.hasWildCardsInSymbolName());

		matcher = new SymbolMatcher("a::b::c", true);
		assertFalse(matcher.hasWildCardsInSymbolName());

		matcher = new SymbolMatcher("a::b::c*", true);
		assertTrue(matcher.hasWildCardsInSymbolName());

		matcher = new SymbolMatcher("a::b*::c", true);
		assertFalse(matcher.hasWildCardsInSymbolName());

	}

	@Test
	public void testBackslash() {
		matcher = new SymbolMatcher("\\", false);
		assertMatches(matcher, "\\");

		matcher = new SymbolMatcher("\\bob\\", false);
		assertMatches(matcher, "\\bob\\");

	}

	private Symbol symbol(String path) {
		String[] split = path.split(Namespace.DELIMITER);
		String name = split[split.length - 1];
		Namespace namespace = getNamespace(split);
		return new TestSymbol(name, namespace);

	}

	private Namespace getNamespace(String[] split) {
		Namespace namespace = null;
		for (int i = 0; i < split.length - 1; i++) {
			namespace = new StubNamespace(split[i], namespace);
		}
		return namespace;
	}

	private void assertMatches(SymbolMatcher symbolMatcher, String path) {
		Symbol s = symbol(path);
		assertTrue(symbolMatcher.matches(s));
	}

	private void assertNotMatches(SymbolMatcher symbolMatcher, String path) {
		Symbol s = symbol(path);
		assertFalse(symbolMatcher.matches(s));
	}

	private class TestMemoryBlock extends MemoryBlockStub {
		@Override
		public String getName() {
			return ".text";
		}
	}

	private class TestMemory extends StubMemory {
		@Override
		public MemoryBlock getBlock(Address addr) {
			return new TestMemoryBlock();
		}
	}

	private class TestProgram extends StubProgram {
		@Override
		public Memory getMemory() {
			return new TestMemory();
		}
	}

	private class TestSymbol extends StubSymbol {

		public TestSymbol(String name, Namespace parent) {
			super(name, parent);
		}

		@Override
		public Program getProgram() {
			return new TestProgram();
		}
	}
}
