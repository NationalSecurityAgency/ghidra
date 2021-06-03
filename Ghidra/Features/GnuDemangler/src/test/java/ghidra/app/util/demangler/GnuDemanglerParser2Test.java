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
package ghidra.app.util.demangler;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.demangler.gnu.GnuDemanglerParser;

public class GnuDemanglerParser2Test extends AbstractGenericTest {

	private GnuDemanglerParser parser = new GnuDemanglerParser();

	//@Test
	public void test1() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypeC1Eii", "OpTestType::OpTestType(int, int)");
		String name = object.getName();
		assertEquals("", name);
	}

	//@Test
	public void test2() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypeC2Eii", "OpTestType::OpTestType(int, int)");
		String name = object.getName();
		assertEquals("", name);
	}

	@Test
	public void test3() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypeclEf", "OpTestType::operator()(float)");
		String name = object.getName();
		assertEquals("operator()", name);
	}

	@Test
	public void test4() {

		DemangledObject object = parser.parse("_ZN10OpTestTypeclEi", "OpTestType::operator()(int)");
		String name = object.getName();
		assertEquals("operator()", name);
	}

	//@Test
	public void test5() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypecvN16Names", "_ZN10OpTestTypecvN16Names");
		String name = object.getName();
		assertEquals("", name);
	}

	@Test
	public void test6() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypecvPKcEv", "OpTestType::operator char const*()");
		String name = object.getName();
		assertEquals("operator.cast.to.char*", name);
	}

	@Test
	public void test7() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypedaEPv", "OpTestType::operator delete[](void*)");
		String name = object.getName();
		assertEquals("operator.delete[]", name);
	}

	@Test
	public void test8() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypedlEPv", "OpTestType::operator delete(void*)");
		String name = object.getName();
		assertEquals("operator.delete", name);
	}

	@Test
	public void test9() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypemIERKS_", "OpTestType::operator-=(OpTestType const&)");
		String name = object.getName();
		assertEquals("operator-=", name);
	}

	@Test
	public void test10() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypemiERKS_", "OpTestType::operator-(OpTestType const&)");
		String name = object.getName();
		assertEquals("operator-", name);
	}

	@Test
	public void test11() {

		DemangledObject object = parser.parse("_ZN10OpTestTypemmEi", "OpTestType::operator--(int)");
		String name = object.getName();
		assertEquals("operator--", name);
	}

	@Test
	public void test12() {

		DemangledObject object = parser.parse("_ZN10OpTestTypemmEv", "OpTestType::operator--()");
		String name = object.getName();
		assertEquals("operator--", name);
	}

	@Test
	public void test13() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypenaEm", "OpTestType::operator new[](unsigned long)");
		String name = object.getName();
		assertEquals("operator.new[]", name);
	}

	@Test
	public void test14() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypenwEm", "OpTestType::operator new(unsigned long)");
		String name = object.getName();
		assertEquals("operator.new", name);
	}

	@Test
	public void test15() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypepLERKS_", "OpTestType::operator+=(OpTestType const&)");
		String name = object.getName();
		assertEquals("operator+=", name);
	}

	@Test
	public void test16() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypeplERKS_", "OpTestType::operator+(OpTestType const&)");
		String name = object.getName();
		assertEquals("operator+", name);
	}

	@Test
	public void test17() {

		DemangledObject object = parser.parse("_ZN10OpTestTypeppEi", "OpTestType::operator++(int)");
		String name = object.getName();
		assertEquals("operator++", name);
	}

	@Test
	public void test18() {

		DemangledObject object = parser.parse("_ZN10OpTestTypeppEv", "OpTestType::operator++()");
		String name = object.getName();
		assertEquals("operator++", name);
	}

//--------------------
//TODO: for the following, determine what arguments are needed.

	@Test
	public void testOperatorNew() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypenwEm", "OpTestType::operator new(unsigned long)");
		String name = object.getName();
		assertEquals("operator.new", name);
	}

	@Test
	public void testOperatorDelete() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypedlEPv", "OpTestType::operator delete(void*)");
		String name = object.getName();
		assertEquals("operator.delete", name);
	}

	@Test
	public void testOperatorAssignment() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator=()");
		String name = object.getName();
		assertEquals("operator=", name);
	}

	@Test
	public void testOperatorRightShift() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator>>()");
		String name = object.getName();
		assertEquals("operator>>", name);
	}

	@Test
	public void testOperatorLeftShift() {

		DemangledObject object =
			parser.parse("_ZN11myContainerIiElsEi", "myContainer<int>::operator<<(int)");
		String name = object.getName();
		assertEquals("operator<<", name);
	}

	@Test
	public void testOperatorLeftShiftTemplated() {

		DemangledObject object = parser.parse("_ZN11myContainerIiElsIdEEbT_",
			"bool myContainer<int>::operator<< <double>(double)");
		String name = object.getName();
		assertEquals("operator<<", name);
		assertEquals("bool myContainer<int>::operator<<<double>(double)",
			object.getSignature());
	}

	@Test
	public void testOperatorLogicalNot() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator!()");
		String name = object.getName();
		assertEquals("operator!", name);
	}

	@Test
	public void testOperatorEquality() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator==()");
		String name = object.getName();
		assertEquals("operator==", name);
	}

	@Test
	public void testOperatorInequality() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator!=()");
		String name = object.getName();
		assertEquals("operator!=", name);
	}

	@Test
	public void testOperatorArraySubscript() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator[]()");
		String name = object.getName();
		assertEquals("operator[]", name);
	}

	@Test
	public void testOperatorTypeCast() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypecvPKcEv", "OpTestType::operator char const*()");
		String name = object.getName();
		assertEquals("operator.cast.to.char*", name);
	}

	@Test
	public void testOperatorTypeCast_WithNamespace() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypecvN16NamespaceOpTest116NamespaceOpTest210CastToTypeEEv",
				"OpTestType::operator NamespaceOpTest1::NamespaceOpTest2::CastToType()");
		assertName(object, "operator.cast.to.CastToType", "OpTestType");
		assertEquals(
			"NamespaceOpTest1::NamespaceOpTest2::CastToType OpTestType::operator.cast.to.CastToType(void)",
			object.getSignature());
	}

	@Test
	public void testOperatorPointerDereference() {
		DemangledObject object = parser.parse("fake", "OpTestType::operator->()");
		String name = object.getName();
		assertEquals("operator->", name);
	}

	@Test
	public void testOperatorMultiplication() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator*()");
		String name = object.getName();
		assertEquals("operator*", name);
	}

	//TODO: If laying down function signatures, then we need to investigate whether we can
	// determine prefix vs. postfix increment.  Postfix will have an argument and prefix will not.
	// Same for prefix vs. postfix decrement.
	@Test
	public void testOperatorPrefixIncrement() {

		DemangledObject object = parser.parse("_ZN10OpTestTypeppEv", "OpTestType::operator++()");
		String name = object.getName();
		assertEquals("operator++", name);
	}

	@Test
	public void testOperatorPostfixIncrement() {

		DemangledObject object = parser.parse("_ZN10OpTestTypeppEi", "OpTestType::operator++(int)");
		String name = object.getName();
		assertEquals("operator++", name);
	}

	@Test
	public void testOperatorPrefixDecrement() {

		DemangledObject object = parser.parse("_ZN10OpTestTypemmEv", "OpTestType::operator--()");
		String name = object.getName();
		assertEquals("operator--", name);
	}

	@Test
	public void testOperatorPostfixDecrement() {

		DemangledObject object = parser.parse("_ZN10OpTestTypemmEi", "OpTestType::operator--(int)");
		String name = object.getName();
		assertEquals("operator--", name);
	}

	@Test
	public void testOperatorSubtraction() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypemiERKS_", "OpTestType::operator-(OpTestType const&)");
		String name = object.getName();
		assertEquals("operator-", name);
	}

	@Test
	public void testOperatorAddition() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypeplERKS_", "OpTestType::operator+(OpTestType const&)");
		String name = object.getName();
		assertEquals("operator+", name);
	}

	@Test
	public void testOperatorAddressOf() {

		DemangledObject object = parser.parse("_ZN10SmallClassadEv", "SmallClass::operator&()");
		String name = object.getName();
		assertEquals("operator&", name);
	}

	@Test
	public void testOperatorPointerToMemberSelection() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator->*()");
		String name = object.getName();
		assertEquals("operator->*", name);
	}

	@Test
	public void testOperatorDivision() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator/()");
		String name = object.getName();
		assertEquals("operator/", name);
	}

	@Test
	public void testOperatorModulus() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator%()");
		String name = object.getName();
		assertEquals("operator%", name);
	}

	@Test
	public void testOperatorLessThan() {

		DemangledObject object =
			parser.parse("_ZN11myContainerIiEltEi", "myContainer<int>::operator<(int)");
		String name = object.getName();
		assertEquals("operator<", name);
	}

	@Test
	public void testOperatorLessThanTemplated() {

		DemangledObject object = parser.parse("_ZltI11myContainerIiEEbRKT_S4_",
			"bool operator< <myContainer<int> >(myContainer<int> const&, myContainer<int> const&)");
		String name = object.getName();
		assertEquals("operator<", name);
		assertEquals(
			"bool operator<<myContainer<int>>(myContainer<int> const &,myContainer<int> const &)",
			object.getSignature());
	}

	@Test
	public void testOperatorLessThanOrEqualTo() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator<=()");
		String name = object.getName();
		assertEquals("operator<=", name);
	}

	@Test
	public void testOperatorGreaterThan() {

		DemangledObject object = parser.parse("_ZgtRK10complex_ldS1_",
			"operator>(complex_ld const&, complex_ld const&)");
		String name = object.getName();
		assertEquals("operator>", name);
	}

	@Test
	public void testOperatorGreaterThanOrEqualTo() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator>=()");
		String name = object.getName();
		assertEquals("operator>=", name);
	}

	@Test
	public void testOperatorComma() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator,()");
		String name = object.getName();
		assertEquals("operator,", name);
	}

	@Test
	public void testOperatorFunctionCall() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypeclEf", "OpTestType::operator()(float)");
		String name = object.getName();
		assertEquals("operator()", name);
	}

	@Test
	public void testOperatorOnesComplement() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator~()");
		String name = object.getName();
		assertEquals("operator~", name);
	}

	@Test
	public void testOperatorExclusiveOr() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator^()");
		String name = object.getName();
		assertEquals("operator^", name);
	}

	@Test
	public void testOperatorBitwiseInclusiveOr() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator|()");
		String name = object.getName();
		assertEquals("operator|", name);
	}

	@Test
	public void testOperatorLogicalAnd() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator&&()");
		String name = object.getName();
		assertEquals("operator&&", name);
	}

	@Test
	public void testOperatorLogicalOr() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator||()");
		String name = object.getName();
		assertEquals("operator||", name);
	}

	@Test
	public void testOperatorMultiplicationAssignment() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator*=()");
		String name = object.getName();
		assertEquals("operator*=", name);
	}

	@Test
	public void testOperatorAdditionAssignment() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypepLERKS_", "OpTestType::operator+=(OpTestType const&)");
		String name = object.getName();
		assertEquals("operator+=", name);
	}

	@Test
	public void testOperatorSubtractionAssignment() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypemIERKS_", "OpTestType::operator-=(OpTestType const&)");
		String name = object.getName();
		assertEquals("operator-=", name);
	}

	@Test
	public void testOperatorDivisionAssignment() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator/=()");
		String name = object.getName();
		assertEquals("operator/=", name);
	}

	@Test
	public void testOperatorModulusAssignment() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator%=()");
		String name = object.getName();
		assertEquals("operator%=", name);
	}

	@Test
	public void testOperatorRightShiftAssignment() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator>>=()");
		String name = object.getName();
		assertEquals("operator>>=", name);
	}

	@Test
	public void testOperatorLeftShiftAssignment() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator<<=()");
		String name = object.getName();
		assertEquals("operator<<=", name);
	}

	@Test
	public void testOperatorBitwiseAndAssignment() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator&=()");
		String name = object.getName();
		assertEquals("operator&=", name);
	}

	@Test
	public void testOperatorBitwiseOrAssignment() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator|=()");
		String name = object.getName();
		assertEquals("operator|=", name);
	}

	@Test
	public void testOperatorExclusiveOrAssignment() {

		DemangledObject object = parser.parse("fake", "OpTestType::operator^=()");
		String name = object.getName();
		assertEquals("operator^=", name);
	}

	@Test
	public void testOperatorNewArray() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypenaEm", "OpTestType::operator new[](unsigned long)");
		String name = object.getName();
		assertEquals("operator.new[]", name);
	}

	@Test
	public void testOperatorDeleteArray() {

		DemangledObject object =
			parser.parse("_ZN10OpTestTypedaEPv", "OpTestType::operator delete[](void*)");
		String name = object.getName();
		assertEquals("operator.delete[]", name);
	}

	@Test
	public void testOperatorUserDefinedLiteral() {

		DemangledObject object =
			parser.parse("_Zli5_initPKcm", "operator\"\" _init(char const*, unsigned long)");
		String name = object.getName();
		assertEquals("operator\"\"__init", name);
	}

	private void assertName(DemangledObject demangledObj, String name, String... namespaces) {

		assertEquals("Unexpected demangled name", name, demangledObj.getName());
		Demangled namespace = demangledObj.getNamespace();
		for (int i = namespaces.length - 1; i >= 0; i--) {
			String expectedName = namespaces[i];
			assertNotNull("Namespace mismatch", namespace);
			String actualName = namespace.getNamespaceName();
			assertEquals(expectedName, actualName);
			namespace = namespace.getNamespace();
		}
		assertNull("Namespace mismatch", namespace);
	}
}
