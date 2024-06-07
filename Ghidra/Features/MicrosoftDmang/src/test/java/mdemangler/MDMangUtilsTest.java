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

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.SymbolPath;
import mdemangler.datatype.MDDataType;

/**
 * This class performs testing of MDMangUtils methods
 */
public class MDMangUtilsTest extends AbstractGenericTest {

	@Test
	public void testWithLambdaAndSimpleConversionApplies() throws Exception {
		// From record number 604770
		//  We cared about the lambda because this is a situation where we need to deal
		//  with nested types that were causing problems for PDB
		String mangled = ".?AV<lambda_0>@?0??name0@name1@@YA?AUname2@2@Uname3@2@Uname4@2@@Z@";
		String expected =
			"`struct name1::name2 __cdecl name1::name0(struct name1::name3,struct name1::name4)'::`1'::<lambda_0>";
		String simpleExpected = "name1::name0::`1'::<lambda_0>";
		String expectedDemangled =
			"class `struct name1::name2 __cdecl name1::name0(struct name1::name3,struct name1::name4)'::`1'::<lambda_0>";

		MDMangGhidra demangler = new MDMangGhidra();
		MDDataType item = demangler.demangleType(mangled, true);

		String demangled = item.toString();
		SymbolPath symbolPath = MDMangUtils.getSymbolPath(item);
		SymbolPath simpleSymbolPath = MDMangUtils.getSimpleSymbolPath(item);
		String result = symbolPath.getPath();
		String simpleResult = simpleSymbolPath.getPath();

		assertEquals(expected, result);
		assertEquals(simpleExpected, simpleResult);
		assertEquals(expectedDemangled, demangled);
	}

	@Test
	public void testTypeNamespaceSimpleConversionDoesNotApply1() throws Exception {
		String mangled =
			".?AU?$name0@$$QEAV<lambda_0>@?0??name1@name2@?Aname3@name4@@UEAAXVname5@4@HAEBVname6@4@@Z@@name7@name8@@";
		String expected =
			"name8::name7::name0<class `public: virtual void __cdecl name4::`anonymous namespace'::name2::name1(class Aname3::name5,int,class Aname3::name6 const & __ptr64) __ptr64'::`1'::<lambda_0> && __ptr64>";
		// See MDMangUtils.getSimpleSymbolPath(item) javadoc to understand why expected and
		//  simpleExpected are the same
		String simpleExpected = expected;
		String expectedDemangled =
			"struct name8::name7::name0<class `public: virtual void __cdecl name4::`anonymous namespace'::name2::name1(class Aname3::name5,int,class Aname3::name6 const & __ptr64) __ptr64'::`1'::<lambda_0> && __ptr64>";

		MDMangGhidra demangler = new MDMangGhidra();
		MDDataType item = demangler.demangleType(mangled, true);

		String demangled = item.toString();
		SymbolPath symbolPath = MDMangUtils.getSymbolPath(item);
		SymbolPath simpleSymbolPath = MDMangUtils.getSimpleSymbolPath(item);
		String result = symbolPath.getPath();
		String simpleResult = simpleSymbolPath.getPath();

		assertEquals(expected, result);
		assertEquals(simpleExpected, simpleResult);
		assertEquals(expectedDemangled, demangled);
	}

	@Test
	public void testTypeNamespaceSimpleConversionDoesNotApply2() throws Exception {
		String mangled = ".?AU?$name0@$$QEAV<lambda_0>@?0???1Aname1@name2@@UEAA@XZ@@name3@name4@@";
		String expected =
			"name4::name3::name0<class `public: virtual __cdecl name2::Aname1::~Aname1(void) __ptr64'::`1'::<lambda_0> && __ptr64>";
		// See MDMangUtils.getSimpleSymbolPath(item) javadoc to understand why expected and
		//  simpleExpected are the same
		String simpleExpected = expected;
		String expectedDemangled =
			"struct name4::name3::name0<class `public: virtual __cdecl name2::Aname1::~Aname1(void) __ptr64'::`1'::<lambda_0> && __ptr64>";

		MDMangGhidra demangler = new MDMangGhidra();
		MDDataType item = demangler.demangleType(mangled, true);

		String demangled = item.toString();
		SymbolPath symbolPath = MDMangUtils.getSymbolPath(item);
		SymbolPath simpleSymbolPath = MDMangUtils.getSimpleSymbolPath(item);
		String result = symbolPath.getPath();
		String simpleResult = simpleSymbolPath.getPath();

		assertEquals(expected, result);
		assertEquals(simpleExpected, simpleResult);
		assertEquals(expectedDemangled, demangled);
	}

}
