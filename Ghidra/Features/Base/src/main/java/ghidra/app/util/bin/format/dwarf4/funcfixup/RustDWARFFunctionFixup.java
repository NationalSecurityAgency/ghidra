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
package ghidra.app.util.bin.format.dwarf4.funcfixup;

import ghidra.app.util.bin.format.dwarf4.DIEAggregate;
import ghidra.app.util.bin.format.dwarf4.DWARFException;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFSourceLanguage;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunction;
import ghidra.program.model.listing.Function;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * Prevent functions in a Rust compile unit from incorrectly being locked down to an empty signature. 
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_NORMAL_EARLY)
public class RustDWARFFunctionFixup implements DWARFFunctionFixup {

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc, Function gfunc) throws DWARFException {
		DIEAggregate diea = dfunc.diea;
		int cuLang = diea.getCompilationUnit().getCompileUnit().getLanguage();
		if (cuLang == DWARFSourceLanguage.DW_LANG_Rust && dfunc.params.isEmpty()) {
			// if there were no defined parameters and the language is Rust, don't force an
			// empty param signature. Rust language emit dwarf info without types (signatures)
			// when used without -g.
			throw new DWARFException("Rust empty param list" /* string doesnt matter */);
		}
	}

}
