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
import ghidra.app.util.demangler.DemangledObject;

/**
 * This class performs extra demangler testing for special cases that do not fit
 * the testing pattern found in MDMangBaseTest and its derived test classes.
 */
public class MDMangExtraTest extends AbstractGenericTest {

	@Test
	//This test checks that we can provide a mangled string for a function namespace.
	// The return String from getOriginalMangled() is not null only for this special
	// circumstance.  So, in normal processing, we should check it for non-null to
	// determine that we have a result of this form.
	// The symbol here is from our cn3.cpp source target.
	public void testFunctionNamespace() throws Exception {
		String mangled = "?fn3@?2??Bar3@Foo2b@@SAHXZ@4HA";
		String wholeTruth = "int `public: static int __cdecl Foo2b::Bar3(void)'::`3'::fn3";
		String functionNamespaceMangledTruth = "?Bar3@Foo2b@@SAHXZ";
		String functionNamespaceTruth = "public: static int __cdecl Foo2b::Bar3(void)";

		MDMangGhidra demangler = new MDMangGhidra();
		MDParsableItem item = demangler.demangle(mangled, true);

		String demangled = item.toString();
		assertEquals(wholeTruth, demangled);
		DemangledObject obj = demangler.getObject();
		String mangledFunctionNamespace = obj.getNamespace().getNamespace().getMangledString();
		assertEquals(functionNamespaceMangledTruth, mangledFunctionNamespace);

		item = demangler.demangle(mangledFunctionNamespace, true);
		demangled = item.toString();
		assertEquals(functionNamespaceTruth, demangled);
	}
}
