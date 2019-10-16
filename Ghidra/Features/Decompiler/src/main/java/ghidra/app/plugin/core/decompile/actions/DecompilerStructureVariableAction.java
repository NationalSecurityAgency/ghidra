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
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.UndefinedFunction;

public class DecompilerStructureVariableAction extends CreateStructureVariableAction {

	public DecompilerStructureVariableAction(String owner, PluginTool tool,
			DecompilerController controller) {
		super(owner, tool, controller);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {

		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
		return decompilerContext.checkActionEnablement(() -> {

			Function function = controller.getFunction();
			if (function == null || function instanceof UndefinedFunction) {
				return false;
			}

			DataType dt = null;
			boolean isThisParam = false;

			// get the data type at the location and see if it is OK
			DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
			ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
			if (tokenAtCursor == null) {
				return false;
			}
			int maxPointerSize = controller.getProgram().getDefaultPointerSize();
			HighVariable var = tokenAtCursor.getHighVariable();
			if (var != null && !(var instanceof HighConstant)) {
				dt = var.getDataType();
				isThisParam = testForAutoParameterThis(var, function);
			}

			if (dt == null || dt.getLength() > maxPointerSize) {
				return false;
			}

			adjustCreateStructureMenuText(dt, isThisParam);
			return true;

		});
	}
}
