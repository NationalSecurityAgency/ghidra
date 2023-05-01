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

import ghidra.app.util.bin.format.dwarf4.next.DWARFFunction;
import ghidra.app.util.bin.format.dwarf4.next.DWARFVariable;
import ghidra.program.model.listing.Function;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * Steal storage location from parameters that are defined in a function's local variable
 * area, because the storage location isn't the parameter location during call, but its location
 * after being spilled.
 * 
 * Create a local variable at that storage location.
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_NORMAL_LATE)
public class ParamSpillDWARFFunctionFixup implements DWARFFunctionFixup {

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc, Function gfunc) {
		for (DWARFVariable param : dfunc.params) {
			if (!param.isStackStorage()) {
				continue;
			}
			long paramStackOffset = param.getStackOffset();
			if (dfunc.isInLocalVarStorageArea(paramStackOffset) &&
				dfunc.getLocalVarByOffset(paramStackOffset) == null) {

				DWARFVariable paramSpill = DWARFVariable.fromDataType(dfunc, param.type);
				String paramName = param.name.getName();
				paramSpill.name =
					param.name.replaceName(paramName + "-local", paramName + "-local");
				paramSpill.setStackStorage(paramStackOffset);
				dfunc.localVars.add(paramSpill);
				param.clearStorage();
			}
		}
	}

}
