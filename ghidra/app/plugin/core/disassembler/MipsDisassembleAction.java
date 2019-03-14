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

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Action for Mips mode disassembly
 */

class MipsDisassembleAction extends ListingContextAction {

	private DisassemblerPlugin plugin;
	private boolean disassembleMIPS16 = false;
	String groupName;

	public MipsDisassembleAction(DisassemblerPlugin plugin, String groupName,
			boolean disassembleMIPS16) {
		super("Disassemble " + (disassembleMIPS16 ? "MIPS16/Micromips" : "MIPS"), plugin.getName());
		this.groupName = groupName;
		this.plugin = plugin;
		this.disassembleMIPS16 = disassembleMIPS16;

		// Need to override the default help location since this action doesn't have its own
		// section in the help.
		HelpLocation location = new HelpLocation("DisassemblerPlugin", "Disassemble");
		this.setHelpLocation(location);

		// menu data will be adjusted based upon specific popup context
		setPopupMenuData(new MenuData(new String[] { "Disassemble - MIPS" }, null, groupName));

		int keyEvent = (disassembleMIPS16 ? KeyEvent.VK_F12 : KeyEvent.VK_F11);
		setKeyBindingData(new KeyBindingData(keyEvent, 0));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.disassembleMipsCallback(context, disassembleMIPS16);
	}

	@Override
	protected boolean isAddToPopup(ListingActionContext context) {

		if (!isEnabledForContext(context)) {
			return false;
		}

		// Prior to returning, we are resetting the menu action to match that of the language ID.
		// this could not be done up in the constructor since the program has not been set yet.

		String alternateMips = null;

		String langName =
			context.getProgram().getLanguage().getLanguageDescription().getLanguageID().getIdAsString();
		if (langName.contains("micro") || langName.contains("R6")) {
			alternateMips = "MicroMips";
		}
		else {
			alternateMips = "Mips16e";
		}

		setPopupMenuData(new MenuData(
			new String[] { "Disassemble - " + (disassembleMIPS16 ? alternateMips : "MIPS") }, null,
			groupName));

		return true;
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {

		Address address = context.getAddress();
		if (address == null) {
			return false;
		}

		Program program = context.getProgram();
		Language lang = program.getLanguage();
		Processor proc = lang.getProcessor();

		if (!"MIPS".equals(proc.toString())) {
			return false;
		}

		Register register = context.getProgram().getProgramContext().getRegister("ISA_MODE");
		if (register == null) {
			return false;
		}

		return plugin.checkDisassemblyEnabled(context, address, true);

	}
}
