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
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

public class X86_64DisassembleAction extends ListingContextAction {
	private final DisassemblerPlugin plugin;
	private final boolean disassemble32Bit;

	public X86_64DisassembleAction(DisassemblerPlugin plugin, String groupName,
			boolean disassemble32Bit) {
		super("Disassemble " + (disassemble32Bit ? "32" : "64") + "-bit x86", plugin.getName());

		this.plugin = plugin;
		this.disassemble32Bit = disassemble32Bit;

		setPopupMenuData(new MenuData(new String[] { getName() }, null, groupName));

		int keyEvent = (disassemble32Bit ? KeyEvent.VK_F12 : KeyEvent.VK_F11);
		setKeyBindingData(new KeyBindingData(keyEvent, 0));

		// Need to override the default help location since this action doesn't have its own
		// section in the help.
		HelpLocation location = new HelpLocation("DisassemblerPlugin", "Disassemble");
		this.setHelpLocation(location);
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.disassembleX86_64Callback(context, disassemble32Bit);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		// STOPGAP: Disable these in the static context
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}

		Address address = context.getAddress();
		if (address == null) {
			return false;
		}

		Program program = context.getProgram();
		Language lang = program.getLanguage();
		Processor proc = lang.getProcessor();
		/*
		 * Action only intended for use where 64-bit x86 is available. I'm just going to check for
		 * x86 with size 64.
		 */
		if (!"x86".equals(proc.toString())) {
			return false;
		}
		if (lang.getLanguageDescription().getSize() != 64) {
			return false;
		}

		return plugin.checkDisassemblyEnabled(context, address, true);
	}
}
