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
package ghidra.app.util.bin.format.dwarf.funcfixup;

import ghidra.app.util.bin.format.dwarf.DWARFFunction;
import ghidra.app.util.bin.format.dwarf.DWARFVariable;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * Complains about function parameters that are marked as 'output' and don't have storage
 * locations.
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_NORMAL_LATE)
public class OutputParamCheckDWARFFunctionFixup implements DWARFFunctionFixup {

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc) {
		// Complain about parameters that are marked as 'output' that haven't been handled by
		// some other fixup, as we don't know what to do with them.
		for (DWARFVariable dvar : dfunc.params) {
			if (dvar.isOutputParameter && dvar.isMissingStorage()) {
				String paramName = dvar.name.getName();
				dfunc.getProgram()
						.logWarningAt(dfunc.address, dfunc.name.getName(),
							"Unsupported output parameter %s".formatted(paramName));
			}
		}
	}
}
