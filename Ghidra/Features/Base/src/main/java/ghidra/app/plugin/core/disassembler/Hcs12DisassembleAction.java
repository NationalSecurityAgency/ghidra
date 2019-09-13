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
 * Action for HCS12 mode disassembly
 */

class Hcs12DisassembleAction extends ListingContextAction {
	private DisassemblerPlugin plugin;
	private boolean disassembleXgate = false;

	public Hcs12DisassembleAction(DisassemblerPlugin plugin, String groupName, boolean disassembleXgate) {
		super("Disassemble " + (disassembleXgate ? "HCS12" : "XGate"), plugin.getName());
		
		this.plugin = plugin;
		this.disassembleXgate = disassembleXgate;

		// Need to override the default help location since this action doesn't have its own
		// section in the help.
		HelpLocation location = new HelpLocation("DisassemblerPlugin", "Disassemble");
		this.setHelpLocation(location);
		
		setPopupMenuData( new MenuData( 
			new String[]{"Disassemble - "+ (disassembleXgate ? "XGate" : "HCS12") }, 
			null, 
			groupName ) );
		
		int keyEvent = (disassembleXgate ? KeyEvent.VK_F12 : KeyEvent.VK_F11);
		setKeyBindingData( new KeyBindingData( keyEvent, 0 ) );
	}
	
	@Override
    public void actionPerformed(ListingActionContext context) {
		plugin.disassembleHcs12Callback(context, disassembleXgate);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {

		// Action only intended for use where Xgate instructions are available.
		// The presence of the XGATE context register can be used for this 
		// determination.
		
		Address address = context.getAddress();
		if ( address == null ) {
		    return false;
		}
		
		Program program = context.getProgram();
		Language lang = program.getLanguage();
		Processor proc = lang.getProcessor();

		if (!"HCS12".equals(proc.toString())) {
			return false;
		}
		
		Register register = context.getProgram().getProgramContext().getRegister("XGATE");
		if (register == null) {
			return false;
		}

		return plugin.checkDisassemblyEnabled(context, address, true);
	}
}
