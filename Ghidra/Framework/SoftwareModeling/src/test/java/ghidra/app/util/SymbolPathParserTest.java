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

import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;

import org.junit.Ignore;
import org.junit.Test;

import generic.test.AbstractGTest;

public class SymbolPathParserTest extends AbstractGTest {

	@Test
	public void testNullString() {
		try {
			SymbolPathParser.parse(null);
			fail();
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testJustSymbolNameNoPath() {
		List<String> list = SymbolPathParser.parse("bob");
		List<String> expected = new ArrayList<>();
		expected.add("bob");
		assertListEqualOrdered(expected, list);
	}

	@Test
	public void testSymbolPathGivenPathString() {
		List<String> list = SymbolPathParser.parse("aaa::bbb::bob");
		List<String> expected = new ArrayList<>();
		expected.add("aaa");
		expected.add("bbb");
		expected.add("bob");
		assertListEqualOrdered(expected, list);
	}

	@Test
	public void testCliArray() {
		List<String> list = SymbolPathParser.parse(
			"namespace::ta<cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64>");
		List<String> expected = new ArrayList<>();
		expected.add("namespace");
		expected.add("ta<cli::array<wchar_t ,2>^,class System::Text::Encoding ^ __ptr64>");
		assertListEqualOrdered(expected, list);
	}

	@Test
	public void testNamespaceInFunctionArgument() {
		List<String> list = SymbolPathParser.parse("Foo7::Bar5(class Foo1d::Bar1,int)");
		List<String> expected = new ArrayList<>();
		expected.add("Foo7");
		expected.add("Bar5(class Foo1d::Bar1,int)");
		assertListEqualOrdered(expected, list);
	}

	// Testing for only doing naive processing--expecting less-than-perfect results.
	// Eliminate this test and use the one below when detailed processing is in place.
	@Test
	public void testCliPinptrMSFTVersion_NaiveProcessing() {
		List<String> list = SymbolPathParser.parse("namespace::ta<cli::pin_ptr" +
			"<unsigned char * __ptr64,class System::Text::Encoding ^ __ptr64>");
		List<String> expected = new ArrayList<>();
		expected.add("namespace");
		expected.add("ta<cli");
		expected.add("pin_ptr<unsigned char * __ptr64,class System");
		expected.add("Text");
		expected.add("Encoding ^ __ptr64>");
		assertListEqualOrdered(expected, list);
	}

	// Testing for detailed processing.  Same as above test, but expecting better results.
	@Ignore
	public void testCliPinptrMSFTVersion_DetailedProcessing() {
		List<String> list = SymbolPathParser.parse("namespace::ta<cli::pin_ptr" +
			"<unsigned char * __ptr64,class System::Text::Encoding ^ __ptr64>");
		List<String> expected = new ArrayList<>();
		expected.add("namespace");
		expected.add(
			"ta<cli::pin_ptr<unsigned char * __ptr64,class System::Text::Encoding ^ __ptr64>");
		assertListEqualOrdered(expected, list);
	}

	@Test
	public void testTemplateMoreComplicated1() {
		String name = "E::F<class E::D::G<struct E::D::H<bool (__cdecl*const)" +
			"(enum C::B const &),0>,bool,enum C::B const &> >::" +
			"F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>," +
			"bool,enum C::B const &> ><class E::D::A<bool,enum C::B const &> >";
		List<String> list = SymbolPathParser.parse(name);
		List<String> expected = new ArrayList<>();
		expected.add("E");
		expected.add("F<class E::D::G<struct E::D::H<bool (__cdecl*const)" +
			"(enum C::B const &),0>,bool,enum C::B const &> >");
		expected.add("F<class E::D::G<struct E::D::H<bool (__cdecl*const)(enum C::B const &),0>," +
			"bool,enum C::B const &> ><class E::D::A<bool,enum C::B const &> >");
		assertListEqualOrdered(expected, list);
	}

	@Test
	public void testSpecialCharAfterDelimiter1() {
		String name = "A::B::C<wchar_t,A::B::D<wchar_t>,A::B::E<wchar_t> >::<unnamed-tag>";
		List<String> list = SymbolPathParser.parse(name);
		List<String> expected = new ArrayList<>();
		expected.add("A");
		expected.add("B");
		expected.add("C<wchar_t,A::B::D<wchar_t>,A::B::E<wchar_t> >");
		expected.add("<unnamed-tag>");
		assertListEqualOrdered(expected, list);
	}

	@Test
	public void testUnmatchedAngleBracketFallback1() {
		// Contrived example to test naive parsing going into fallback mode due to unmatched
		//  angle brackets.  The expected result here is not an accurate result that we would
		//  expect from a more sophisticated parser.
		String name = "A::operator<=::B<C<int>::<unnamed-tag>>::E";
		List<String> list = SymbolPathParser.parse(name);
		List<String> expected = new ArrayList<>();
		expected.add("A");
		expected.add("operator<=");
		expected.add("B<C<int>");
		expected.add("<unnamed-tag>>");
		expected.add("E");
		assertListEqualOrdered(expected, list);
	}

}
