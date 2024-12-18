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
package mdemangler;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import mdemangler.datatype.MDDataType;
import mdemangler.naming.MDQualification;
import mdemangler.object.MDObjectCPP;
import mdemangler.typeinfo.MDVxTable;

/**
 * This class performs extra demangler testing for special cases that do not fit
 * the testing pattern found in MDMangBaseTest and its derived test classes.
 */
public class MDMangExtraTest extends AbstractGenericTest {

	@Test
	public void testVxTableNestedQualifications() throws Exception {
		// Test string taken from MDMangBaseTest
		String mangled = "??_7a@b@@6Bc@d@e@@f@g@h@@i@j@k@@@";
		String truth = "const b::a::`vftable'{for `e::d::c's `h::g::f's `k::j::i'}";

		MDMangGhidra demangler = new MDMangGhidra();
		demangler.setMangledSymbol(mangled);
		demangler.setErrorOnRemainingChars(true);
		demangler.setDemangleOnlyKnownPatterns(true);
		MDParsableItem item = demangler.demangle();

		String demangled = item.toString();
		assertEquals(truth, demangled);

		MDObjectCPP cppItem = (MDObjectCPP) item;
		MDVxTable vxTable = (MDVxTable) cppItem.getTypeInfo();
		List<MDQualification> qualifications = vxTable.getNestedQualifications();
		assertEquals(3, qualifications.size());
		assertEquals("e::d::c", qualifications.get(0).toString());
		assertEquals("h::g::f", qualifications.get(1).toString());
		assertEquals("k::j::i", qualifications.get(2).toString());
	}

	// Backref used in parentage
	@Test
	public void testVxTableNestedQualificationWithBackref() throws Exception {
		String mangled = "??_7a@b@@6B01@@";
		String truth = "const b::a::`vftable'{for `b::a'}";

		MDMangGhidra demangler = new MDMangGhidra();
		demangler.setMangledSymbol(mangled);
		demangler.setErrorOnRemainingChars(true);
		demangler.setDemangleOnlyKnownPatterns(true);
		MDParsableItem item = demangler.demangle();

		String demangled = item.toString();
		assertEquals(truth, demangled);

		MDObjectCPP cppItem = (MDObjectCPP) item;
		MDVxTable vxTable = (MDVxTable) cppItem.getTypeInfo();
		List<MDQualification> qualifications = vxTable.getNestedQualifications();
		assertEquals(1, qualifications.size());
		assertEquals("b::a", qualifications.get(0).toString());
	}

	// Anonymous namespace in owner and backref
	@Test
	public void testVxTableAnonymousNsInOwner() throws Exception {
		String mangled = "??_7a@?A0xfedcba98@b@@6B@";
		String truth = "const b::`anonymous namespace'::a::`vftable'";
		String truth2 = "const b::_anon_FEDCBA98::a::`vftable'";

		MDMangGhidra demangler = new MDMangGhidra();
		demangler.setMangledSymbol(mangled);
		demangler.setErrorOnRemainingChars(true);
		demangler.setDemangleOnlyKnownPatterns(true);
		MDParsableItem item = demangler.demangle();

		MDObjectCPP cppItem = (MDObjectCPP) item;
		MDVxTable vxTable = (MDVxTable) cppItem.getTypeInfo();
		List<MDQualification> qualifications = vxTable.getNestedQualifications();
		assertEquals(0, qualifications.size());

		String demangled = item.toString();
		assertEquals(truth, demangled);

		demangler.getOutputOptions().setUseEncodedAnonymousNamespace(true);
		demangled = item.toString();
		assertEquals(truth2, demangled);
	}

	// Anonymous namespace in owner and backref
	@Test
	public void testVxTableAnonymousNsInOwnerAndBackref() throws Exception {
		String mangled = "??_7a@?A0xfedcba98@b@@6B012@01@@";
		String truth =
			"const b::`anonymous namespace'::a::`vftable'{for `b::A0xfedcba98::a's `A0xfedcba98::a'}";
		String truth2 =
			"const b::_anon_FEDCBA98::a::`vftable'{for `b::_anon_FEDCBA98::a's `_anon_FEDCBA98::a'}";

		MDMangGhidra demangler = new MDMangGhidra();
		demangler.setMangledSymbol(mangled);
		demangler.setErrorOnRemainingChars(true);
		demangler.setDemangleOnlyKnownPatterns(true);
		MDParsableItem item = demangler.demangle();

		MDObjectCPP cppItem = (MDObjectCPP) item;
		MDVxTable vxTable = (MDVxTable) cppItem.getTypeInfo();
		List<MDQualification> qualifications = vxTable.getNestedQualifications();
		assertEquals(2, qualifications.size());

		String demangled = item.toString();
		assertEquals(truth, demangled);
		assertEquals("b::A0xfedcba98::a", qualifications.get(0).toString());
		assertEquals("A0xfedcba98::a", qualifications.get(1).toString());

		demangler.getOutputOptions().setUseEncodedAnonymousNamespace(true);
		demangled = item.toString();
		assertEquals(truth2, demangled);
		assertEquals("b::_anon_FEDCBA98::a", qualifications.get(0).toString());
		assertEquals("_anon_FEDCBA98::a", qualifications.get(1).toString());
	}

	@Test
	public void testSimpleDemangleType() throws Exception {
		String mangled = ".?AUname0@name1@@";
		String expected = "struct name1::name0";

		MDMangGhidra demangler = new MDMangGhidra();
		demangler.setMangledSymbol(mangled);
		demangler.setErrorOnRemainingChars(true);
		MDDataType item = demangler.demangleType();

		String demangled = item.toString();
		assertEquals(expected, demangled);
	}

	// Need to test the demangleType() method to make sure it does the retry with LLVM mode
	@Test
	public void testDemangleTypeWithRetry() throws Exception {
		// Test string taken from MDMangBaseTest
		String mangled = ".?AW4name0@?name1@name2@@YAX_N@Z@";
		String truth = "enum `void __cdecl name2::name1(bool)'::name0";

		MDMangGhidra demangler = new MDMangGhidra();
		demangler.setMangledSymbol(mangled);
		demangler.setErrorOnRemainingChars(true);
		MDParsableItem item = demangler.demangleType(); // note demangleType()

		String demangled = item.toString();
		assertEquals(truth, demangled);
	}

}
