/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;

class DisassembleAction extends ListingContextAction {
	private DisassemblerPlugin plugin;

	public DisassembleAction(DisassemblerPlugin plugin, String groupName) {
		super("Disassemble", plugin.getName());
		
		this.plugin = plugin;
		
		setPopupMenuData( new MenuData( new String[]{"Disassemble" }, null, groupName ) );
		setKeyBindingData( new KeyBindingData( KeyEvent.VK_D, 0 ) );
	}
	
	@Override
    public void actionPerformed(ListingActionContext context) {
		plugin.disassembleCallback(context);
	}
	
	@Override
    public boolean isEnabledForContext(ListingActionContext context) {	    
		Address address = context.getAddress();
		if ( address == null ) {
		    return false;
		}
        return plugin.checkDisassemblyEnabled(context, address, true);
	}
	
}
