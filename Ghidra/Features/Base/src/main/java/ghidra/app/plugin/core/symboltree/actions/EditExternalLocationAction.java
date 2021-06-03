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
package ghidra.app.plugin.core.symboltree.actions;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.plugin.core.symboltree.EditExternalLocationDialog;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;

/**
 * A local action intended for components which supply a {@link ProgramSymbolActionContext} which
 * facilitates editing an external location symbol.
 */
public class EditExternalLocationAction extends DockingAction {

	private static ImageIcon EDIT_ICON = null;

	private final Plugin plugin;

	/**
	 * Creates the action for editing an existing external location or external function in the 
	 * symbol tree.
	 * @param plugin the symbol tree plugin, which owns this action.
	 */
	public EditExternalLocationAction(Plugin plugin) {
		super("Edit External Location", plugin.getName());
		this.plugin = plugin;
		this.setPopupMenuData(
			new MenuData(new String[] { "Edit External Location" }, EDIT_ICON, "0External"));
		setEnabled(true);
	}

	private Symbol getExternalSymbol(ActionContext context) {
		Symbol s = null;
		if (context instanceof ProgramSymbolActionContext) {
			ProgramSymbolActionContext symbolContext = (ProgramSymbolActionContext) context;
			if (symbolContext.getSymbolCount() != 1) {
				return null;
			}
			s = symbolContext.getFirstSymbol();
		}
		if (s == null || !s.isExternal()) {
			return null;
		}
		if (s.getSymbolType() == SymbolType.LABEL || s.getSymbolType() == SymbolType.FUNCTION) {
			return s;
		}
		return null;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return getExternalSymbol(context) != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Symbol symbol = getExternalSymbol(context);
		if (symbol == null) {
			return;
		}

		ExternalManager externalManager = symbol.getProgram().getExternalManager();
		ExternalLocation externalLocation = externalManager.getExternalLocation(symbol);
		if (externalLocation == null) {
			return; // assume symbol has been deleted
		}

		final EditExternalLocationDialog dialog = new EditExternalLocationDialog(externalLocation);

		dialog.setHelpLocation(new HelpLocation(plugin.getName(), "EditExternalLocation"));
		plugin.getTool().showDialog(dialog);
	}

}
