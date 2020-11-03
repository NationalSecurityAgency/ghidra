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
package ghidra.app.plugin.core.label;

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.OperandFieldLocation;

/**
 * <CODE>AddLabelAction</CODE> allows the user to add a label.
 */
class EditLabelAction extends ListingContextAction {
	private LabelMgrPlugin plugin;

	static final String EDIT_LABEL = "Edit Label...";
	static final String EDIT_FIELDNAME = "Edit Field Name...";

	private static final String[] POPUP_PATH = { EDIT_LABEL };
	private static final KeyStroke KEYBINDING = KeyStroke.getKeyStroke(KeyEvent.VK_L, 0);

	/**
	 * Creates a new instance of the action.
	 *
	 * @param plugin Label Manager Plugin instance
	 */
	EditLabelAction(LabelMgrPlugin plugin) {
		super("Edit Label", plugin.getName());

		setPopupMenuData(new MenuData(POPUP_PATH, null, "Label"));
		setKeyBindingData(new KeyBindingData(KEYBINDING));

		// Set the Group

		this.plugin = plugin;
		setEnabled(true);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		Symbol symbol = plugin.getSymbol(context);
		if (symbol != null) {
			if (symbol.isExternal()) {
				return false;
			}
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				// let the rename function action handle this
				return false;
			}
			getPopupMenuData().setMenuItemName(EDIT_LABEL);
			return true;
		}
		if (LabelMgrPlugin.getComponent(context) != null) {
			getPopupMenuData().setMenuItemName(EDIT_FIELDNAME);
			return true;
		}
		return false;
	}

	boolean isOnSymbol(ListingActionContext context) {
		if (context.getLocation() instanceof LabelFieldLocation) {
			return plugin.isOnSymbol(context);
		}
		else if (context.getLocation() instanceof OperandFieldLocation) {
			Symbol s = plugin.getSymbol(context);
			return (s instanceof CodeSymbol);
		}
		return false;
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.editLabelCallback(context);
	}

}
