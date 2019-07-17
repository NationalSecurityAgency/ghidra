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
package ghidra.app.plugin.core.function;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.cmd.function.CreateExternalFunctionCmd;
import ghidra.app.context.*;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

public class CreateExternalFunctionAction extends ProgramContextAction {

	FunctionPlugin plugin;

	public CreateExternalFunctionAction(String name, FunctionPlugin plugin) {
		super(name, plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(
			new MenuData(new String[] { name }, null, FunctionPlugin.FUNCTION_MENU_SUBGROUP,
				MenuData.NO_MNEMONIC, FunctionPlugin.FUNCTION_SUBGROUP_BEGINNING));

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, 0));

		setHelpLocation(new HelpLocation("FunctionPlugin", "ExternalFunctions"));

		setEnabled(true);
	}

	private Symbol getExternalCodeSymbol(ListingActionContext listingContext) {

		Program program = listingContext.getProgram();

		ProgramSelection selection = listingContext.getSelection();
		if (selection != null && !selection.isEmpty()) {
			return null;
		}

		ProgramLocation location = listingContext.getLocation();
		if (location instanceof OperandFieldLocation) {
			OperandFieldLocation opLoc = (OperandFieldLocation) location;
			ReferenceManager refMgr = program.getReferenceManager();
			Reference ref =
				refMgr.getPrimaryReferenceFrom(opLoc.getAddress(), opLoc.getOperandIndex());
			if (ref != null && ref.isExternalReference()) {
				Symbol s = program.getSymbolTable().getPrimarySymbol(ref.getToAddress());
				if (s.getSymbolType() == SymbolType.LABEL) {
					return s;
				}
			}
		}
		return null;
	}

	@Override
	protected boolean isEnabledForContext(ProgramActionContext context) {

		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			return getExternalCodeSymbol(listingContext) != null;
		}
		else if (context instanceof ProgramSymbolActionContext) {
			ProgramSymbolActionContext symbolContext = (ProgramSymbolActionContext) context;
			if (symbolContext.getSymbolCount() == 0) {
				return false;
			}
			for (Symbol s : symbolContext.getSymbols()) {
				if (!s.isExternal() || s.getSymbolType() != SymbolType.LABEL) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	@Override
	protected void actionPerformed(ProgramActionContext context) {
		CompoundCmd compoundCmd = null;
		CreateExternalFunctionCmd cmd = null;
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			cmd = new CreateExternalFunctionCmd(getExternalCodeSymbol(listingContext));
		}
		else if (context instanceof ProgramSymbolActionContext) {
			ProgramSymbolActionContext symbolContext = (ProgramSymbolActionContext) context;
			for (Symbol s : symbolContext.getSymbols()) {
				CreateExternalFunctionCmd extFuncCmd = new CreateExternalFunctionCmd(s);
				if (cmd != null) {
					if (compoundCmd == null) {
						compoundCmd = new CompoundCmd("Create External Functions");
						compoundCmd.add(cmd);
					}
					compoundCmd.add(extFuncCmd);
				}
				else {
					cmd = extFuncCmd;
				}
			}
		}
		if (cmd == null) {
			return; // assume all selected symbols have been deleted
		}
		if (compoundCmd != null) {
			plugin.execute(context.getProgram(), compoundCmd);
		}
		else {
			plugin.execute(context.getProgram(), cmd);
		}
	}

}
