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
package ghidra.program.model.symbol;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class IllegalCharCppTransformerTest extends AbstractGenericTest {

	private IllegalCharCppTransformer transformer = new IllegalCharCppTransformer();

	@Test
	public void testTemplateChars() {
		assertEquals("foo<bar>", simplify("foo<bar>"));
		assertEquals("foo<std::bar>", simplify("foo<std::bar>"));
		assertEquals("map<int,char*>", simplify("map<int,char*>"));
		assertEquals("pair<vec1,(*)(char[12]),const&val>",
			simplify("pair<vec1,(*)(char[12]),const&val>"));
		assertEquals("_basic_string<char,std::char_traits<char>>",
			simplify("_basic.string<char,std::char_traits<char>>"));
		assertEquals("_________baz", simplify("*()~[]&:,baz"));
		assertEquals("foo12___<std::space__::vec>___bar__operator",
			simplify("foo12 ??<std::space??::vec>_*~bar::operator"));
	}

	@Test
	public void testOperatorChars() {
		assertEquals("operator<<", simplify("operator<<"));
		assertEquals("operator>>=", simplify("operator>>="));
		assertEquals("operator++", simplify("operator++"));
		assertEquals("operator/=", simplify("operator/="));
		assertEquals("operator%", simplify("operator%"));
		assertEquals("operator&&", simplify("operator&&"));
		assertEquals("operator!=", simplify("operator!="));
		assertEquals("operator__", simplify("operator.?"));
		assertEquals("operator~", simplify("operator~"));
		assertEquals("operator^", simplify("operator^"));
		assertEquals("myoperator__", simplify("myoperator!="));
	}

	@Test
	public void testBadChars() {
		assertEquals("~destructor_main", simplify("~destructor.main"));
		assertEquals("~Vector_7", simplify("~Vector~7"));
		assertEquals("_2foo", simplify("12foo"));
		assertEquals("std__foo", simplify("std::foo"));
		assertEquals("bar__1", simplify("bar??1"));
		assertEquals("_resource_352_", simplify("[resource.352]"));
		assertEquals("_val_", simplify("!val%"));
		// Foreign language identifiers
		assertEquals("\u041d\u0415\u0422", simplify("\u041d\u0415\u0422"));
	}

	private String simplify(String in) {
		return transformer.simplify(in);
	}
}
