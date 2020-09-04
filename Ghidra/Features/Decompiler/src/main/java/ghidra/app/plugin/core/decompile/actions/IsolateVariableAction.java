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

import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

public class IsolateVariableAction extends AbstractDecompilerAction {

	public IsolateVariableAction() {
		super("Split Out As New Variable");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionIsolate"));
		setPopupMenuData(new MenuData(new String[] { "Split Out As New Variable" }, "Decompile"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		HighVariable variable = tokenAtCursor.getHighVariable();
		if (!(variable instanceof HighLocal)) {
			return false;
		}
		HighSymbol highSymbol = variable.getSymbol();
		if (highSymbol == null) {
			return false;
		}
		if (highSymbol.isIsolated()) {
			return false;
		}

		Varnode vn = tokenAtCursor.getVarnode();
		if (vn == null) {
			return false;
		}
		short mergeGroup = vn.getMergeGroup();
		boolean mergeSplit = false;
		for (Varnode var : variable.getInstances()) {
			if (var.getMergeGroup() != mergeGroup) {
				mergeSplit = true;
				break;
			}
		}
		if (!mergeSplit) {
			return false;
		}
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		final ClangToken tokenAtCursor = context.getTokenAtCursor();
		HighSymbol highSymbol = tokenAtCursor.getHighVariable().getSymbol();
		IsolateVariableTask newVariableTask =
			new IsolateVariableTask(context.getTool(), context.getProgram(),
				context.getDecompilerPanel(), tokenAtCursor, highSymbol, SourceType.USER_DEFINED);

		newVariableTask.runTask(false);
	}

}
