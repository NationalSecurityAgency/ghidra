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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.util.OperandFieldLocation;

/**
 * <CODE>AddLabelAction</CODE> allows the user to add a label.
 */
class SetOperandLabelAction extends ListingContextAction {
	private LabelMgrPlugin plugin;
	private static final String[] POPUP_PATH = { "Set Associated Label..." };
	private static final KeyStroke KEYBINDING =
		KeyStroke.getKeyStroke(KeyEvent.VK_L, InputEvent.CTRL_MASK | InputEvent.ALT_MASK);

	/**
	 * Creates a new instance of the action.
	 *
	 * @param plugin Label Manager Plugin instance
	 */
	SetOperandLabelAction(LabelMgrPlugin plugin) {
		super("Set Operand Label", plugin.getName());

		setPopupMenuData(new MenuData(POPUP_PATH, null, "Label"));
		setKeyBindingData(new KeyBindingData(KEYBINDING));

		this.plugin = plugin;
		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		if (!(context.getLocation() instanceof OperandFieldLocation)) {
			return false;
		}
		return !plugin.isOnExternalReference(context) && !plugin.isOnVariableReference(context) &&
			plugin.isOnSymbol(context);
	}

	/**
	 * Method called when the action is invoked.
	 * @param ActionEvent details regarding the invocation of this action
	 */
	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.setOperandLabelCallback(context);
	}

}
