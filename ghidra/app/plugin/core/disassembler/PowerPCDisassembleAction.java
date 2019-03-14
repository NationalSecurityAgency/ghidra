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
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Action for PPC mode disassembly when VLE instruction support is present
 */

class PowerPCDisassembleAction extends ListingContextAction {
	private DisassemblerPlugin plugin;
	private boolean disassemblePPC = false;
	String groupName;

	public PowerPCDisassembleAction(DisassemblerPlugin plugin, String groupName,
			boolean disassemblePPC) {
		super("Disassemble " + (disassemblePPC ? "PPC-VLE" : "PPC"), plugin.getName());
		this.groupName = groupName;
		this.plugin = plugin;
		this.disassemblePPC = disassemblePPC;

		// Need to override the default help location since this action doesn't have its own
		// section in the help.
		HelpLocation location = new HelpLocation("DisassemblerPlugin", "Disassemble");
		this.setHelpLocation(location);

		initializeContextMenu();

		int keyEvent = (disassemblePPC ? KeyEvent.VK_F12 : KeyEvent.VK_F11);
		setKeyBindingData(new KeyBindingData(keyEvent, 0));
	}

	public void initializeContextMenu() {
		setPopupMenuData(
			new MenuData(new String[] { "Disassemble - " + (disassemblePPC ? "PPC-VLE" : "PPC") },
				null, groupName));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.disassemblePPCCallback(context, disassemblePPC);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {

		Address address = context.getAddress();
		if (address == null) {
			return false;
		}

		// Action only intended for use where PowerPC VLE instructions are available.
		// The presence of the VLE variant indicator in the language ID can be used for this 
		// determination.

		Program program = context.getProgram();
		Language lang = program.getLanguage();
		Processor proc = lang.getProcessor();

		if (!proc.equals(Processor.findOrPossiblyCreateProcessor("PowerPC")) ||
			lang.getLanguageID().toString().indexOf(":VLE") < 0) {
			return false;
		}

		return plugin.checkDisassemblyEnabled(context, address, true);
	}

}
