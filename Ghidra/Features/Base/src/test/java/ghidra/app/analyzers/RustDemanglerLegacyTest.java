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
package ghidra.app.analyzers;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.plugin.core.analysis.rust.demangler.RustDemangler;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.lang.CompilerSpec;

public class RustDemanglerLegacyTest {

	private static final String RUSTCALL = CompilerSpec.CALLING_CONVENTION_rustcall;

	private static String[] symbols =
		{ "_ZN43_$LT$char$u20$as$u20$core..fmt..Display$GT$3fmt17h31c4c24bbd08aa24E",
			"_ZN4core6option13expect_failed17h09b982639336e7eaE",
			"_ZN4core3fmt9Formatter15debug_lower_hex17heb5fb064687c1b3cE",
			"_ZN3std4path10Components7as_path17h3cc3e688e3107704E",
			"_ZN5alloc5alloc18handle_alloc_error8rt_error17h4b79f8a717741b7cE",
			"_ZN3std6thread7current17h20e47a880e55afd5E", };

	private static String[] names = { RUSTCALL + " _<char_as_core::fmt::Display>::fmt(void)",
		RUSTCALL + " core::option::expect_failed(void)",
		RUSTCALL + " core::fmt::Formatter::debug_lower_hex(void)",
		RUSTCALL + " std::path::Components::as_path(void)",
		RUSTCALL + " alloc::alloc::handle_alloc_error::rt_error(void)",
		RUSTCALL + " std::thread::current(void)",
		RUSTCALL + " gimli::read::abbrev::Attributes::new(void)" };

	@Test
	public void demangle() {
		RustDemangler demangler = new RustDemangler();
		for (int i = 0; i < symbols.length; i++) {
			String mangled = symbols[i];
			String name = names[i];

			try {
				DemangledObject demangled = demangler.demangle(mangled);
				if (!name.equals(demangled.toString())) {
					fail("Demangled symbol to wrong name \n" + demangled + "\n" + name);
				}
			}
			catch (DemangledException e) {
				fail("Couldn't demangle symbol " + mangled);
			}
		}
	}
}
