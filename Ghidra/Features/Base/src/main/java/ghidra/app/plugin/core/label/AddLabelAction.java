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

/**
 * <CODE>AddLabelAction</CODE> allows the user to add a label.
 */
class AddLabelAction extends ListingContextAction {
	private LabelMgrPlugin plugin;

	private static final String[] POPUP_PATH = { "Add Label..." };
	private static final KeyStroke KEYBINDING = KeyStroke.getKeyStroke(KeyEvent.VK_L, 0);

	/**
	 * Creates a new instance of the action.
	 *
	 * @param plugin Label Manager Plugin instance
	 */
	AddLabelAction(LabelMgrPlugin plugin) {
		super("Add Label", plugin.getName());
		setPopupMenuData(new MenuData(POPUP_PATH, null, "Label"));
		setKeyBindingData(new KeyBindingData(KEYBINDING));

		this.plugin = plugin;
		setEnabled(true);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.getAddress().isExternalAddress()) {
			return false;
		}
		int[] componentPath = context.getLocation().getComponentPath();
		if (componentPath != null && componentPath.length != 0) {
			return false;
		}
		return !plugin.isOnVariableReference(context) && !plugin.isOnSymbol(context) &&
			!plugin.isOnFunction(context);
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.addLabelCallback(context);
	}

}
