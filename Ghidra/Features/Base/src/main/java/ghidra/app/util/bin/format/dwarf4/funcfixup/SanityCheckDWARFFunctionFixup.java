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

import ghidra.app.util.bin.format.dwarf4.DWARFException;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFAttributeValue;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunction;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * Check for errors and prevent probable bad function info from being locked in
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_NORMAL_LATE)
public class SanityCheckDWARFFunctionFixup implements DWARFFunctionFixup, DWARFAttributeValue {

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc, Function gfunc) throws DWARFException {
		// if there were no defined parameters and we had problems decoding local variables,
		// don't force the method to have an empty param signature because there are other
		// issues afoot.
		if (dfunc.params.isEmpty() && dfunc.localVarErrors) {
			Msg.error(this,
				String.format(
					"Inconsistent function signature information, leaving undefined: %s@%s",
					gfunc.getName(), gfunc.getEntryPoint()));
			throw new DWARFException("Failed sanity check");
		}
	}

}
