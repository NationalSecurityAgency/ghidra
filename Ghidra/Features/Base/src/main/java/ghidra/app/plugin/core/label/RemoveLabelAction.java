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

import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

/**
 * <CODE>RemoveLabelAction</CODE> allows the user to remove a label.
 */
class RemoveLabelAction extends ListingContextAction {
	private LabelMgrPlugin plugin;

	private static final String[] POPUP_PATH = { "Remove Label" };
	private static final KeyStroke KEYBINDING = KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0);

	/**
	 * Creates a new instance of the action.
	 *
	 * @param plugin Label Manager Plugin instance
	 */
	RemoveLabelAction(LabelMgrPlugin plugin) {
		super("Remove Label", plugin.getName());

		// the above sets the default (preferred) values, but not the actuals
		// below we indicate that the popup and keybinding are also needed
		setPopupMenuData(new MenuData(POPUP_PATH, null, "Label"));
		setKeyBindingData(new KeyBindingData(KEYBINDING));

		// Set the Group

		this.plugin = plugin;
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.removeLabelCallback(context);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		return !plugin.isOnExternalReference(context) && isOnSymbol(context);
	}

	boolean isOnSymbol(ListingActionContext context) {
		Symbol s = plugin.getSymbol(context);
		return ((s instanceof CodeSymbol) && !s.isDynamic()) ||
			((s instanceof FunctionSymbol) && s.getSource() != SourceType.DEFAULT);
	}

	/**
	 * @see DockingAction#dispose()
	 */
	@Override
	public void dispose() {
		super.dispose();
		plugin = null;
	}

}
