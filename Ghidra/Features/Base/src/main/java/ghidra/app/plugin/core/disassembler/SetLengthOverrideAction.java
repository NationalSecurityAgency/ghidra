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
package ghidra.app.plugin.core.disassembler;

import db.Transaction;
import docking.action.MenuData;
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;

class SetLengthOverrideAction extends ListingContextAction {

	private DisassemblerPlugin plugin;

	public SetLengthOverrideAction(DisassemblerPlugin plugin, String groupName) {
		super("Modify Instruction Length", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(
			new MenuData(new String[] { "Modify Instruction Length..." }, null, groupName));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {

		PluginTool tool = plugin.getTool();

		Address address = context.getAddress();
		if (address == null) {
			return;
		}
		Program program = context.getProgram();
		Listing listing = program.getListing();
		Instruction instr = listing.getInstructionAt(address);
		if (instr == null) {
			return;
		}

		int protoLen = instr.getPrototype().getLength();
		if (protoLen == 1) {
			Msg.showError(this, null, "Length Override Error",
				"Length override for 1-byte instruction not allowed");
			return;
		}

		String restoreTip = ", 0=restore";

		String alignTip = "";
		int align = program.getLanguage().getInstructionAlignment();
		if (align != 1) {
			alignTip = ", must be multiple of " + align;
		}

		int minLength = 0;
		long maxLength = Math.min(Instruction.MAX_LENGTH_OVERRIDE, protoLen - 1);
		Instruction nextInstr = listing.getInstructionAfter(address);
		if (nextInstr != null &&
			nextInstr.getAddress().getAddressSpace().equals(address.getAddressSpace())) {
			long limit = nextInstr.getAddress().subtract(address);
			maxLength = Math.min(limit, maxLength);
			if (limit < instr.getParsedLength()) {
				minLength = 1; // unable to restore to default length using 0 value
				restoreTip = "";
			}
		}

		if (maxLength == 0) {
			// Assume we have an instruction whose length can't be changed
			Msg.showError(this, null, "Length Override Error",
				"Insufficient space to alter current length override of 1-byte");
			return;
		}

		int currentLengthOverride = 0;
		if (instr.isLengthOverridden()) {
			currentLengthOverride = instr.getLength();
		}

		NumberInputDialog dialog = new NumberInputDialog("Override/Restore Instruction Length",
			"Enter byte-length [" + minLength + ".." + maxLength + restoreTip + alignTip + "]",
			currentLengthOverride, minLength, (int) maxLength, false);
		tool.showDialog(dialog);

		if (dialog.wasCancelled()) {
			return;
		}

		String kind = "Set";
		int lengthOverride = dialog.getIntValue();
		if (lengthOverride == 0) {
			if (!instr.isLengthOverridden()) {
				return; // no change
			}
			kind = "Clear";
		}

		try (Transaction tx = instr.getProgram().openTransaction(kind + " Length Override")) {
			instr.setLengthOverride(lengthOverride);
		}
		catch (CodeUnitInsertionException e) {
			Msg.showError(this, null, "Length Override Error", e.getMessage());
		}
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		Address address = context.getAddress();
		if (address == null) {
			return false;
		}
		Program program = context.getProgram();
		Instruction instr = program.getListing().getInstructionAt(address);
		if (instr == null) {
			return false;
		}
		int alignment = program.getLanguage().getInstructionAlignment();
		return instr.getParsedLength() > alignment;
	}

}
