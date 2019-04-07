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
package ghidra.app.plugin.core.function;

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import docking.action.MenuData;

/**
 * <CODE>EditStructureAction</CODE> allows the user to edit a structure.
 */
class EditStructureAction extends ListingContextAction {
	private FunctionPlugin plugin;

	private static final String[] POPUP_PATH = { FunctionPlugin.SET_DATA_TYPE_PULLRIGHT,
		"Edit Structure..." };

	EditStructureAction(FunctionPlugin plugin) {
		super("Edit Structure", plugin.getName());

		setPopupMenuData(new MenuData(POPUP_PATH, null, "Array"));
		setHelpLocation(new HelpLocation("DataTypeEditors", "Structure_Editor"));

		this.plugin = plugin;
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		Program program = context.getProgram();
		FunctionLocation loc = (FunctionLocation) context.getLocation();
		DataType dt = getDataType(program, loc);
		if (dt instanceof Composite) {
			plugin.getDataTypeManagerService().edit(dt);
		}
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}
		ProgramLocation loc = context.getLocation();
		Program program = context.getProgram();

		if (!(loc instanceof VariableLocation) && !(loc instanceof VariableCommentFieldLocation)) {
			return false;
		}
		DataType dt = getDataType(program, (FunctionLocation) loc);
		if (dt != null && (dt instanceof Composite) && !(dt instanceof BuiltInDataType)) {
			return true;
		}
		return false;

	}

	private DataType getDataType(Program program, FunctionLocation loc) {
		if (program == null) {
			return null;
		}
		Listing listing = program.getListing();
		Function f = listing.getFunctionAt(loc.getAddress());
		if (f == null) {
			return null;
		}
		DataType dt = null;

		if (loc instanceof FunctionSignatureFieldLocation) {
			dt = f.getReturnType();
		}
		else {
			Variable var = getVariable(f, loc);
			if (var != null) {
				dt = var.getDataType();
			}
		}
		// if the data type is a pointer, dig out what it points to!
		if (dt instanceof Pointer) {
			Pointer pdt = (Pointer) dt;
			dt = pdt.getDataType();
		}
		return dt;
	}

	/**
	 * Get a variable using the current location.
	 * @param function
	 * @return null if function is null or if current location is not
	 * a stack variable location.
	 */
	private Variable getVariable(Function function, ProgramLocation currentLocation) {
		if (function == null) {
			return null;
		}

		if (currentLocation instanceof VariableLocation) {
			return ((VariableLocation) currentLocation).getVariable();
		}
		return null;
	}

}
