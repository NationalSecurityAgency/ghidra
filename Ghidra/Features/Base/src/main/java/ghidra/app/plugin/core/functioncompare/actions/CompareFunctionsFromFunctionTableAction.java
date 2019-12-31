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
package ghidra.app.plugin.core.functioncompare.actions;

import java.util.*;

import docking.ActionContext;
import ghidra.app.plugin.core.functionwindow.FunctionRowObject;
import ghidra.app.plugin.core.functionwindow.FunctionTableModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.table.GhidraTable;

/**
 * Creates a comparison between a set of functions extracted from selections in
 * a ghidra table. By default this table is assumed to be constructed using a
 * {@link FunctionTableModel}. If the {@link ActionContext context} for 
 * this action does NOT meet those parameters this action will not even be 
 * enabled.
 * <p>
 * If this action is to be used with a different type of table, simply 
 * extend this class and override {@link #getSelectedFunctions(ActionContext) getSelectedFunctions}
 * and {@link #isModelSupported(ActionContext) isModelSupported} as-needed.
 */
public class CompareFunctionsFromFunctionTableAction extends CompareFunctionsAction {

	/**
	 * Constructor
	 * 
	 * @param tool the plugin tool
	 * @param owner the action owner
	 */
	public CompareFunctionsFromFunctionTableAction(PluginTool tool, String owner) {
		super(tool, owner);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return isModelSupported(context);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return isModelSupported(context);
	}

	@Override
	protected Set<Function> getSelectedFunctions(ActionContext actionContext) {
		Set<Function> functions = new HashSet<>();

		GhidraTable table = (GhidraTable) actionContext.getContextObject();
		int[] selectedRows = table.getSelectedRows();
		if (selectedRows.length == 0) {
			return Collections.emptySet();
		}
		FunctionTableModel model = (FunctionTableModel) table.getModel();
		List<FunctionRowObject> functionRowObjects = model.getRowObjects(selectedRows);
		for (FunctionRowObject functionRowObject : functionRowObjects) {
			Function rowFunction = functionRowObject.getFunction();
			functions.add(rowFunction);
		}
		return functions;
	}

	/**
	 * Helper method to determine if the current context is one that this
	 * action supports (eg: is this action being applied to a table that 
	 * contains function information?).
	 * <p>
	 * By default this method verifies that the table in question is a 
	 * {@link FunctionTableModel}. If another table is being used, override this
	 * method.
	 * 
	 * @param context the action context
	 * @return true if the context is a function table model
	 */
	protected boolean isModelSupported(ActionContext context) {
		if (!(context.getContextObject() instanceof GhidraTable)) {
			return false;
		}
		GhidraTable table = (GhidraTable) context.getContextObject();
		return table.getModel() instanceof FunctionTableModel;
	}
}
