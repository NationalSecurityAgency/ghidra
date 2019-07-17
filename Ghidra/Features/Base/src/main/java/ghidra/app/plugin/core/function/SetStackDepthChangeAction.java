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

import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.cmd.function.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.HelpLocation;

/**
 * <CODE>SetStackDepthChangeAction</CODE> allows the user to set a stack depth change value 
 * at the current address.
 */
class SetStackDepthChangeAction extends ListingContextAction {

	/** the plugin associated with this action. */
	FunctionPlugin funcPlugin;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param plugin the plugin this action is associated with.
	 */
	SetStackDepthChangeAction(FunctionPlugin plugin) {
		super("Set Stack Depth Change", plugin.getName());
		this.funcPlugin = plugin;

		setPopupMenuData(new MenuData(
			new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT, "Set Stack Depth Change..." },
			null, FunctionPlugin.FUNCTION_MENU_SUBGROUP));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		final Program program = context.getProgram();
		final Address address = context.getAddress();
		Instruction instr = program.getListing().getInstructionAt(address);
		int oldStackDepthChange = 0;
		final Address callToAddress = getFunctionCallAddress(instr);

		//Get the old stack depth change if it is set.
		Integer change = CallDepthChangeInfo.getStackDepthChange(program, address);
		if (change != null) {
			oldStackDepthChange = change;
		}
		else {
			FunctionManager functionMgr = program.getFunctionManager();
			Function toFunction =
				(callToAddress != null) ? functionMgr.getFunctionAt(callToAddress) : null;
			Function func = functionMgr.getFunctionContaining(address);
			if (toFunction != null) {
				oldStackDepthChange = -(toFunction.getStackPurgeSize());
			}
			else if (func != null) {
				CallDepthChangeInfo callInfo = new CallDepthChangeInfo(func);
				if (instr != null) {
					oldStackDepthChange = callInfo.getInstructionStackDepthChange(instr);
					if (oldStackDepthChange == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
						oldStackDepthChange = 0;
					}
				}
			}
		}

		// Display the dialog.
		String title = "Set Stack Depth Change at " + address.toString();
		NumberInputDialog dialog = new NumberInputDialog(title, "Stack Depth Change",
			oldStackDepthChange, Integer.MIN_VALUE, Integer.MAX_VALUE, false);

		if (!dialog.show()) {
			return;
		}
		int stackDepthChange = dialog.getValue();

		setStackDepthChange(program, address, stackDepthChange, callToAddress);
	}

	private Address getFunctionCallAddress(Instruction instr) {
		if ((instr != null) && instr.getFlowType().isCall()) {
			Program program = instr.getProgram();
			FunctionManager functionMgr = program.getFunctionManager();
			Reference[] refs =
				program.getReferenceManager().getReferencesFrom(instr.getMinAddress());
			for (Reference ref : refs) {
				Address toAddr = ref.getToAddress();
				if (functionMgr.getFunctionAt(toAddr) != null) {
					return toAddr;
				}
			}
		}
		return null;
	}

	private void setStackDepthChange(final Program program, final Address address,
			final int newStackDepthChange, final Address callToAddress) {

		if (callToAddress == null) {
			setStackDepthChange(program, address, newStackDepthChange);
			return;
		}
		int result = showPurgeQuestionDialog(funcPlugin.getTool(), address, callToAddress);
		switch (result) {
			case OptionDialog.OPTION_ONE: // Local (SetStackDepthChange)
				setStackDepthChange(program, address, newStackDepthChange);
				break;
			case OptionDialog.OPTION_TWO: // Global (SetFunctionPurge)
				setFunctionPurge(program, address, newStackDepthChange, callToAddress);
				break;
			case OptionDialog.CANCEL_OPTION: // Cancel
				break;
		}
	}

	private void setFunctionPurge(final Program program, final Address fromAddress,
			final int newFunctionPurgeSize, final Address callToAddress) {
		Function function = program.getFunctionManager().getFunctionAt(callToAddress);
		if (function == null) {
			return;
		}
		// Set the function purge.
		Command purgeCmd = new SetFunctionPurgeCommand(function, newFunctionPurgeSize);

		Integer dephtChange = CallDepthChangeInfo.getStackDepthChange(program, fromAddress);
		if (dephtChange != null) {
			// If we have a stack depth change here, remove it since we are setting the purge.
			CompoundCmd compoundCmd = new CompoundCmd("Set Function Purge via StackDepthChange");
			compoundCmd.add(new RemoveStackDepthChangeCommand(program, fromAddress));
			compoundCmd.add(purgeCmd);
			funcPlugin.execute(program, compoundCmd);
		}
		else {
			funcPlugin.execute(program, purgeCmd);
		}
	}

	// Display dialog to determine if user wants purge or stack depth change.
	private int showPurgeQuestionDialog(final PluginTool tool, final Address currentAddress,
			final Address functionAddress) {

		// @formatter:off
		String message =
			"If this function changes the stack depth (or purge) the same for all calls to the function,\n" +
				"then you should globally set the function purge which affects all calls to the function.\n \n" +
				"If each call to the function affects the stack depth differently, then you should\n" +
				"locally set the stack depth change at the current Call instruction only.\n \n \n" +
				"Choose Global to set the function purge for the Function at " +
				functionAddress.toString() + ".\n" +
				"Choose Local to set the stack depth change for this call only at " +
				currentAddress.toString() + ".";
		// @formatter:on

		StackChangeOptionDialog dialog = new StackChangeOptionDialog(message);
		dialog.show();
		return dialog.getResult();
	}

	private void setStackDepthChange(Program program, Address address, int newStackDepthChange) {
		funcPlugin.execute(program,
			new SetStackDepthChangeCommand(program, address, newStackDepthChange));
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		Address address = context.getAddress();
		if (context.hasSelection() || address == null) {
			return false;
		}

		return true;
	}

	private class StackChangeOptionDialog extends OptionDialog {

		StackChangeOptionDialog(String message) {
			super("Stack Depth Change or Function Purge?", message, "Local", "Global",
				OptionDialog.QUESTION_MESSAGE, null, true);

			setHelpLocation(new HelpLocation(funcPlugin.getName(), "Set_Stack_Depth_Change"));
		}
	}
}
