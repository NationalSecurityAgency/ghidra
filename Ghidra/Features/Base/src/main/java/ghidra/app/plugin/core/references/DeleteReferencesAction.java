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
package ghidra.app.plugin.core.references;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.cmd.refs.RemoveAllReferencesCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.*;

public class DeleteReferencesAction extends ListingContextAction {

	static String DEFAULT_MENU_ITEM_NAME = "Delete References";
	static String MEMORY_MENU_ITEM_NAME = "Delete Memory References";
	static String STACK_MENU_ITEM_NAME = "Delete Stack Reference";
	static String REGISTER_MENU_ITEM_NAME = "Delete Register Reference";
	static String EXTERNAL_MENU_ITEM_NAME = "Delete External Reference";

	private ReferencesPlugin plugin;

	public DeleteReferencesAction(ReferencesPlugin plugin) {
		super("Delete References From", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(
			new String[] { ReferencesPlugin.SUBMENU_NAME,
				DeleteReferencesAction.DEFAULT_MENU_ITEM_NAME },
			null, ReferencesPlugin.SHOW_REFS_GROUP));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		setDescription("Delete all references from a code unit operand");

	}

	@Override
	protected void actionPerformed(ListingActionContext context) {
		int opIndex = ReferenceManager.MNEMONIC;
		ProgramLocation loc = context.getLocation();
		if (loc instanceof OperandFieldLocation) {
			opIndex = ((OperandFieldLocation) loc).getOperandIndex();
		}
		Command cmd = new RemoveAllReferencesCmd(loc.getAddress(), opIndex);
		plugin.getTool().execute(cmd, context.getProgram());
	}

	@Override
	protected boolean isAddToPopup(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();
		return (loc instanceof CodeUnitLocation);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {

		boolean actionOK = false;

		ProgramLocation loc = context.getLocation();
		if (!(loc instanceof CodeUnitLocation)) {
			return false;
		}

		getPopupMenuData().setMenuItemName(DEFAULT_MENU_ITEM_NAME);

		int opIndex;
		if (loc instanceof MnemonicFieldLocation) {
			opIndex = ReferenceManager.MNEMONIC;
		}
		else if (loc instanceof OperandFieldLocation) {
			opIndex = ((OperandFieldLocation) loc).getOperandIndex();
		}
		else {
			setEnabled(false);
			return false;
		}

		Reference[] refs = context.getProgram().getReferenceManager().getReferencesFrom(
			context.getAddress(), opIndex);
		if (refs.length != 0) {
			actionOK = true;
			Address toAddr = refs[0].getToAddress();
			if (toAddr.isMemoryAddress()) {
				getPopupMenuData().setMenuItemName(MEMORY_MENU_ITEM_NAME);
			}
			else if (toAddr.isExternalAddress()) {
				getPopupMenuData().setMenuItemName(EXTERNAL_MENU_ITEM_NAME);
			}
			else if (refs[0].isStackReference()) {
				getPopupMenuData().setMenuItemName(STACK_MENU_ITEM_NAME);
			}
			else if (refs[0].getToAddress().isRegisterAddress()) {
				getPopupMenuData().setMenuItemName(REGISTER_MENU_ITEM_NAME);
			}
			else {
				actionOK = false;
			}
		}
		return actionOK;
	}
}
