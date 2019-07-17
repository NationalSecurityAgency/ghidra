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

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.symboltree.EditExternalLocationDialog;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * An action in the symbol tree for editing an external location or external function.
 */
/**
 * A global listing action which facilitates editing an external location associated
 * with an external reference on an operand field location.
 */
public class EditExternalLabelAction extends ListingContextAction {

	private static ImageIcon EDIT_ICON = null;
	private static final KeyStroke KEYBINDING = KeyStroke.getKeyStroke(KeyEvent.VK_L, 0);

	private LabelMgrPlugin plugin;

	/**
	 * Creates the action for editing an existing external location or external function in the 
	 * listing.
	 * @param plugin the label manager plugin, which owns this action.
	 */
	public EditExternalLabelAction(LabelMgrPlugin plugin) {
		super("Edit External Location", plugin.getName());
		this.plugin = plugin;
		this.setPopupMenuData(
			new MenuData(new String[] { "Edit External Location" }, EDIT_ICON, "0External"));
		setKeyBindingData(new KeyBindingData(KEYBINDING));
		setEnabled(true);
	}

	private Symbol getExternalSymbol(ListingActionContext context) {
		Symbol s = null;
		ProgramLocation location = context.getLocation();
		if (location instanceof OperandFieldLocation) {
			OperandFieldLocation opLoc = (OperandFieldLocation) location;
			Address address = opLoc.getAddress();
			int opIndex = opLoc.getOperandIndex();
			Program program = context.getProgram();
			ReferenceManager refMgr = program.getReferenceManager();
			Reference ref = refMgr.getPrimaryReferenceFrom(address, opIndex);
			if (ref != null) {
				s = program.getSymbolTable().getSymbol(ref);
			}
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
	public boolean isEnabledForContext(ListingActionContext context) {
		return getExternalSymbol(context) != null;
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		Symbol symbol = getExternalSymbol(context);
		if (symbol == null) {
			return;
		}

		ExternalManager externalManager = context.getProgram().getExternalManager();
		ExternalLocation externalLocation = externalManager.getExternalLocation(symbol);
		if (externalLocation == null) {
			return; // assume symbol has been deleted
		}

		final EditExternalLocationDialog dialog = new EditExternalLocationDialog(externalLocation);

		dialog.setHelpLocation(new HelpLocation(HelpTopics.LABEL, "EditExternalLocation"));
		plugin.getTool().showDialog(dialog);
	}

}
