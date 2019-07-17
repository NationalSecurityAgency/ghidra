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


/**
 * Action for Arm mode disassembly
 */

class ArmDisassembleAction extends ListingContextAction {
	private DisassemblerPlugin plugin;
	private boolean disassembleThumb = false;

	public ArmDisassembleAction(DisassemblerPlugin plugin, String groupName, boolean disassembleThumb) {
		super("Disassemble " + (disassembleThumb ? "Thumb" : "Arm"), plugin.getName());
		
		this.plugin = plugin;
		this.disassembleThumb = disassembleThumb;
		
		setPopupMenuData( new MenuData( 
			new String[]{"Disassemble - "+ (disassembleThumb ? "Thumb" : "Arm") }, 
			null, 
			groupName ) );
		
		int keyEvent = (disassembleThumb ? KeyEvent.VK_F12 : KeyEvent.VK_F11);
		setKeyBindingData( new KeyBindingData( keyEvent, 0 ) );
	}
	
	@Override
    public void actionPerformed(ListingActionContext context) {
		plugin.disassembleArmCallback(context, disassembleThumb);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {

		// Action only intended for use where ARM Thumb instructions are available.
		// The presence of the ARM TMode context register can be used for this 
		// determination.
		
		Address address = context.getAddress();
		if ( address == null ) {
		    return false;
		}
		
		Program program = context.getProgram();
		Language lang = program.getLanguage();
		Processor proc = lang.getProcessor();

		if (!"ARM".equals(proc.toString())) {
			return false;
		}
		
		Register register = context.getProgram().getProgramContext().getRegister("TMode");
		if (register == null) {
			return false;
		}

		return plugin.checkDisassemblyEnabled(context, address, true);
	}
}
