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
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

/**
 * Action triggered from a specific token in the decompiler window to rename a local variable.
 * If a matching variable in the database already exists, it is simply renamed. Otherwise
 * a new variable is added to the database. In this case the new variable is assigned
 * an "undefined" datatype, which leaves it un-typelocked, and the decompiler will take
 * the name but lets the data-type continue to "float" and can speculatively merge the
 * variable with others.
 * 
 * If the selected variable is an input parameter, other input parameters within the decompiler
 * model will need to be committed, if they do not already exist in the database, as any parameters
 * committed to the database are forcing on the decompiler. Any new parameters committed this way
 * inherit their name from the decompiler model, but the parameters will not be type-locked, allowing
 * their data-type to "float".
 */
public class RenameLocalAction extends AbstractDecompilerAction {

	public RenameLocalAction() {
		super("Rename Variable");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRenameVariable"));
		setPopupMenuData(new MenuData(new String[] { "Rename Variable" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
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
		if (tokenAtCursor instanceof ClangFieldToken) {
			return false;
		}
		HighSymbol highSymbol = findHighSymbolFromToken(tokenAtCursor, context.getHighFunction());
		if (highSymbol == null) {
			return false;
		}
		return !highSymbol.isGlobal();
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		PluginTool tool = context.getTool();
		final ClangToken tokenAtCursor = context.getTokenAtCursor();
		HighSymbol highSymbol = findHighSymbolFromToken(tokenAtCursor, context.getHighFunction());

		RenameVariableTask nameTask = new RenameVariableTask(tool, context.getProgram(),
			context.getDecompilerPanel(),
			tokenAtCursor, highSymbol, SourceType.USER_DEFINED);

		nameTask.runTask(true);
	}

}
