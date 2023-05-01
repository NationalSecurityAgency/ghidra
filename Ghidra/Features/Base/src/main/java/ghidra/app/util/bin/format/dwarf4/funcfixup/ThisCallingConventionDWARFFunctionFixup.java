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
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * Update the function's calling convention (if unset) if there is a "this" parameter.
 */
@ExtensionPointProperties(priority = DWARFFunctionFixup.PRIORITY_NORMAL)
public class ThisCallingConventionDWARFFunctionFixup implements DWARFFunctionFixup {

	@Override
	public void fixupDWARFFunction(DWARFFunction dfunc, Function gfunc) {
		if (dfunc.params.isEmpty() || dfunc.callingConvention != null) {
			// if someone else set calling convention, don't override it
			return;
		}

		DWARFVariable firstParam = dfunc.params.get(0);
		if (firstParam.isThis) {
			if (!firstParam.name.isAnon() &&
				!Function.THIS_PARAM_NAME.equals(firstParam.name.getOriginalName())) {
				Msg.error(this,
					String.format("WARNING: Renaming %s to %s in function %s@%s",
						firstParam.name.getName(), Function.THIS_PARAM_NAME, gfunc.getName(),
						gfunc.getEntryPoint()));
			}
			firstParam.name =
				firstParam.name.replaceName(Function.THIS_PARAM_NAME, Function.THIS_PARAM_NAME);
			dfunc.callingConvention = GenericCallingConvention.thiscall;
		}
	}

}
