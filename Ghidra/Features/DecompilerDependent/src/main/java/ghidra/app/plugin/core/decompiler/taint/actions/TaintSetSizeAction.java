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
package ghidra.app.plugin.core.decompiler.taint.actions;

import docking.action.MenuData;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompiler.taint.TaintLabel;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin;
import ghidra.app.plugin.core.decompiler.taint.TaintState.MarkType;
import ghidra.program.model.listing.Function;
import ghidra.util.UndefinedFunction;

/**
 * Triggered by right-click on a token in the decompiler window.
 * <p>
 * Action triggered from a specific token in the decompiler window to mark a variable as a
 * source or sink and generate the requisite query. Legal tokens to select include:
 * <ul><li>
 * An input parameter,
 * </li><li>
 * A stack variable, 
 * </li><li>
 * A variable associated with a register, or 
 * </li><li>
 * A "dynamic" variable. 
 * </li></ul>
 */
public class TaintSetSizeAction extends TaintAbstractDecompilerAction {

	private TaintPlugin plugin;

	public TaintSetSizeAction(TaintPlugin plugin) {
		super("Set length");
		// Taint Menu  -> Source sub item.
		setPopupMenuData(new MenuData(new String[] { "Taint", "Set length" }, "Decompile"));
		this.plugin = plugin;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (plugin.getTaintState() == null) {
			return false;
		}

		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			return true;
		}
		if (tokenAtCursor.Parent() instanceof ClangReturnType) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFuncNameToken) {
			return true;
		}
		if (!tokenAtCursor.isVariableRef()) {
			return false;
		}
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		TaintLabel label = plugin.getTaintState().getLabelForToken(MarkType.SOURCE, context.getTokenAtCursor());
		if (label != null) {
			InputDialog dialog = new InputDialog("Update length", "Length", Integer.toHexString(label.getSize()));
			plugin.getTool().showDialog(dialog);
			if (dialog.isCanceled()) {
				return;
			}
			String val = dialog.getValue();
			label.setSize(Integer.parseInt(val, 16));
		}
	}
}
