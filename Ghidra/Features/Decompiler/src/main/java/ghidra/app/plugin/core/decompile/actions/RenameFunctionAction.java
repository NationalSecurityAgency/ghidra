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

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.AddEditDialog;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionShellSymbol;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

public class RenameFunctionAction extends AbstractDecompilerAction {

	public RenameFunctionAction() {
		super("Rename Function");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRenameFunction"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
		setPopupMenuData(new MenuData(new String[] { "Rename Function" }, "Decompile"));
	}

	private Function getFunction(DecompilerActionContext context) {
		Program program = context.getProgram();
		ClangToken tokenAtCursor = context.getTokenAtCursor();

		// try to look up the function that is at the current cursor location
		//   If there isn't one, just use the function we are in.
		if (tokenAtCursor instanceof ClangFuncNameToken) {
			return DecompilerUtils.getFunction(program, (ClangFuncNameToken) tokenAtCursor);
		}
		HighSymbol highSymbol = findHighSymbolFromToken(tokenAtCursor, context.getHighFunction());
		if (highSymbol instanceof HighFunctionShellSymbol) {
			return (Function) highSymbol.getSymbol().getObject();
		}
		return null;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function func = getFunction(context);
		return func != null && !(func instanceof UndefinedFunction);
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		Function function = getFunction(context);
		AddEditDialog dialog = new AddEditDialog("Edit Function Name", context.getTool());
		dialog.editLabel(function.getSymbol(), program);
	}
}
