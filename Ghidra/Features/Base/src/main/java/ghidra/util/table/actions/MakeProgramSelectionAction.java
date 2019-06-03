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
package ghidra.util.table.actions;

import javax.swing.JTable;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * An action to make a program selection based on the given table's selection.  The clients 
 * must implement the make selection code, as they know their own data.  Also, for the context to
 * work, the provider using this action must create an {@link ActionContext} that returns a 
 * context object that is the table passed to this action's constructor.
 */
public abstract class MakeProgramSelectionAction extends DockingAction {

	private JTable table;

	public MakeProgramSelectionAction(String owner, JTable table) {
		super("Make Selection", owner);
		this.table = table;

		setPopupMenuData(
			new MenuData(new String[] { "Make Selection" }, Icons.MAKE_SELECTION_ICON));
		setToolBarData(new ToolBarData(Icons.MAKE_SELECTION_ICON));
		setDescription("Make a program selection from the seleted rows");

		// this help location provides generic help; clients can override to point to their help
		setHelpLocation(new HelpLocation("Search", "Make_Selection"));

		//  null for now, but we may want a default binding in the future
		initKeyStroke(null);
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	@Override
	public boolean usesSharedKeyBinding() {
		return true;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {

		Object contextObject = context.getContextObject();
		if (contextObject != table) {
			return false;
		}

		int n = table.getSelectedRowCount();
		return n > 0;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		makeSelection(context);
	}

	protected abstract void makeSelection(ActionContext context);
}
