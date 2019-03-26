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
import docking.widgets.OptionDialog;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * <CODE>CreateFunctionAction</CODE> allows the user to create a function from
 * a selection in the browser. The AddressSet indicates the function body and
 * the minimum address is used as the entry point to the function.<BR>
 * Action in FunctionPlugin.
 */
class CreateFunctionAction extends ListingContextAction {
	/** the plugin associated with this action. */
	FunctionPlugin funcPlugin;
	boolean allowExisting = false;
	boolean createThunk = false;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param name the name for this action.
	 * @param plugin the plugin this action is associated with.
	 */
	CreateFunctionAction(String name, FunctionPlugin plugin) {
		this(name, plugin, false, false);
	}

	/**
	 * Create a new action, to create a function at the current location with a selection
	 * 
	 * @param string  name of the action
	 * @param functionPlugin does checking for this action
	 * @param allowExisting allow an existing function at this location
	 * @param createThunk if true thunk will be created
	 */
	public CreateFunctionAction(String name, FunctionPlugin plugin, boolean allowExisting,
			boolean createThunk) {
		super(name, plugin.getName());
		this.funcPlugin = plugin;
		this.allowExisting = allowExisting;
		this.createThunk = createThunk;

		if (allowExisting) {
			// top-level item usable only on a function
			setPopupMenuData(
				new MenuData(new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT, name }, null,
					FunctionPlugin.FUNCTION_MENU_SUBGROUP));
		}
		else {
			// top-level item usable most places
			setPopupMenuData(
				new MenuData(new String[] { name }, null, FunctionPlugin.FUNCTION_MENU_SUBGROUP,
					MenuData.NO_MNEMONIC, FunctionPlugin.FUNCTION_SUBGROUP_BEGINNING));
		}

		if (createThunk) {
			setHelpLocation(new HelpLocation("FunctionPlugin", "ThunkFunctions"));
			// TODO: do we want key-binding for thunk creation
		}
		else {
			String anchor = name.replaceAll(" ", "_");
			setHelpLocation(new HelpLocation("FunctionPlugin", anchor));
			if (!allowExisting) {
				setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, 0));
			}
		}

		setEnabled(true);
	}

	/**
	 * Method called when the action is invoked.
	 * @param ActionEvent details regarding the invocation of this action
	 */
	@Override
	public void actionPerformed(ListingActionContext context) {
		Address entry = null;
		AddressSetView body = null;

		if (context.hasSelection()) {
			body = context.getSelection();
			entry = body.getMinAddress();
		}
		else {
			entry = context.getAddress();
		}

		if (entry == null) {
			return;
		}

		String name = null;
		Function func = context.getProgram().getFunctionManager().getFunctionContaining(entry);
		if (func != null && func.getEntryPoint().equals(entry)) {
			if (createThunk) {
				Msg.showError(this, null, "Thunk Conflict",
					"Thunk function conflicts with an existing function!");
				return;
			}
			funcPlugin.getTool().setStatusInfo("Function \"" + func.getName() + "\" at " +
				func.getEntryPoint() + " already exists");
			int result = OptionDialog.showOptionNoCancelDialog(null,
				"Function Already Exists at This Location",
				"Function \"" + func.getName() + "\" at " + func.getEntryPoint() +
					" already exists at this location.\n" +
					"Are you sure you want to proceed?\nDoing so, will cause analysis to be re-run on this function",
				createThunk ? "Create Thunk" : "&Re-create", "&No", OptionDialog.QUESTION_MESSAGE);
			if (result != OptionDialog.OPTION_ONE) {
				return;
			}
			funcPlugin.getTool().clearStatusInfo();
		}

		BackgroundCommand cmd;
		if (createThunk) {
			cmd = getCreateThunkFunctionCmd(context.getProgram(), entry, body);
			if (cmd == null) {
				return; // cancelled
			}
		}
		else {
			cmd = new CreateFunctionCmd(name, entry, body, SourceType.USER_DEFINED, allowExisting,
				allowExisting);
		}
		funcPlugin.execute(context.getProgram(), cmd);
	}

	private CreateThunkFunctionCmd getCreateThunkFunctionCmd(Program program, Address entry,
			AddressSetView body) {

		Symbol refSymbol = null;
		Address refAddr = null;

		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		Instruction instr = listing.getInstructionAt(entry);
		if (instr != null && instr.getFlowType().isJump()) {
			Reference indirectRef = null;
			Reference dataRef = null;
			Reference jumpRef = null;
			for (Reference ref : instr.getReferencesFrom()) {
				RefType refType = ref.getReferenceType();
				if (refType == RefType.INDIRECTION) {
					indirectRef = ref;
				}
				else if (refType.isData()) {
					dataRef = ref;
				}
				else if (refType.isJump()) {
					jumpRef = ref;
				}
			}
			if (jumpRef != null) {
				refAddr = jumpRef.getToAddress();
			}
			else if (instr.getFlowType().isComputed()) {
				Reference ref = indirectRef != null ? indirectRef : dataRef;
				if (ref != null) {
					// find indirect destination
					Reference[] refs = refMgr.getReferencesFrom(ref.getToAddress());
					if (refs.length != 0) {
						if (refs[0].isExternalReference()) {
							ExternalLocation extLoc =
								((ExternalReference) refs[0]).getExternalLocation();
							refSymbol = extLoc.getSymbol();
							refAddr = extLoc.getAddress();
						}
						else if (refs[0].isMemoryReference()) {
							refAddr = refs[0].getToAddress();
						}
					}
				}
			}
		}
		else if (body == null || body.getNumAddresses() == 0) {
			Msg.showError(this, funcPlugin.getTool().getActiveWindow(),
				"Create Thunk Function Failed", "Must select thunk function body");
			return null;
		}
		else {
			CodeUnit cu = listing.getCodeUnitAt(entry);
			if (cu != null && new AddressSet(cu.getMinAddress(), cu.getMaxAddress()).equals(body)) {
				Reference ref = cu.getPrimaryReference(0);
				if (ref != null) {
					refAddr = ref.getToAddress();
				}
			}
		}

		if (refSymbol == null && refAddr != null) {
			refSymbol = program.getSymbolTable().getPrimarySymbol(refAddr);
		}

		ThunkReferenceAddressDialog dialog = new ThunkReferenceAddressDialog(funcPlugin.getTool());
		if (refSymbol != null) {
			dialog.showDialog(program, entry, refSymbol);
		}
		else {
			dialog.showDialog(program, entry, refAddr);
		}
		refSymbol = dialog.getSymbol();
		refAddr = dialog.getAddress();

		if (refSymbol != null) {
			return new CreateThunkFunctionCmd(entry, body, refSymbol);
		}
		else if (refAddr != null) {
			return new CreateThunkFunctionCmd(entry, body, refAddr);
		}
		return null;
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		return this.funcPlugin.isCreateFunctionAllowed(context, allowExisting, createThunk);
	}

}
