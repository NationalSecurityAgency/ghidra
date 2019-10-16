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
package ghidra.app.plugin.core.decompile.actions;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;

public class ListingStructureVariableAction extends CreateStructureVariableAction {

	public ListingStructureVariableAction(String owner, PluginTool tool,
			DecompilerController controller) {
		super(owner, tool, controller);
		setPopupMenuData(new MenuData(new String[] { FunctionPlugin.SET_DATA_TYPE_PULLRIGHT,
			"Auto Create Structure" }, "Array"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataType dt = null;
		boolean isThisParam = false;

		if (!(context instanceof ListingActionContext)) {
			return false;
		}

		ListingActionContext listingContext = (ListingActionContext) context;
		// get the data type at the location and see if it is OK
		// make sure what we are over can be mapped to decompiler
		// param, local, etc...

		ProgramLocation location = listingContext.getLocation();
		Program currentProgram = listingContext.getProgram();

		if (location instanceof VariableLocation) {
			VariableLocation varLoc = (VariableLocation) location;
			Variable variable = varLoc.getVariable();
			if (variable instanceof Parameter) {
				if (((Parameter) variable).getAutoParameterType() == AutoParameterType.THIS) {
					isThisParam = true;
				}
			}
			dt = variable.getDataType();
		}
		else if (location instanceof FunctionParameterFieldLocation) {
			FunctionParameterFieldLocation funcPFL = (FunctionParameterFieldLocation) location;
			Parameter parameter = funcPFL.getParameter();
			if (parameter.getAutoParameterType() == AutoParameterType.THIS) {
				isThisParam = true;
			}
			dt = parameter.getDataType();
		}
		else if (location instanceof FunctionReturnTypeFieldLocation) {
			FunctionReturnTypeFieldLocation funcRTFL = (FunctionReturnTypeFieldLocation) location;
			Function func =
				currentProgram.getFunctionManager().getFunctionAt(funcRTFL.getFunctionAddress());
			dt = func.getReturnType();
		}

		int maxPointerSize = currentProgram.getDefaultPointerSize();
		if (dt == null || dt.getLength() > maxPointerSize) {
			return false;
		}

		adjustCreateStructureMenuText(dt, isThisParam);
		return true;
	}
}
