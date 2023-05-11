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

import ghidra.app.util.bin.format.dwarf4.next.*;
import ghidra.program.model.listing.Function;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * Ensures that function parameter names are unique and valid 
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_LAST)
public class ParamNameDWARFFunctionFixup implements DWARFFunctionFixup {

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc, Function gfunc) {

		// Fix any dups among the parameters, to-be-added-local vars, and already present local vars
		NameDeduper nameDeduper = new NameDeduper();
		nameDeduper.addReservedNames(dfunc.getAllParamNames());
		nameDeduper.addReservedNames(dfunc.getAllLocalVariableNames());
		nameDeduper.addUsedNames(dfunc.getNonParamSymbolNames(gfunc));

		for (DWARFVariable param : dfunc.params) {
			String newName = nameDeduper.getUniqueName(param.name.getName());
			if (newName != null) {
				param.name = param.name.replaceName(newName, param.name.getOriginalName());
			}
		}

		for (DWARFVariable localVar : dfunc.localVars) {
			String newName = nameDeduper.getUniqueName(localVar.name.getName());
			if (newName != null) {
				localVar.name = localVar.name.replaceName(newName, localVar.name.getOriginalName());
			}
		}
	}

}
