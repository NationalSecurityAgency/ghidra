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
package ghidra.app.plugin.core.select.reference;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.nav.NavigationUtils;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

public class SelectBackRefsAction extends NavigatableContextAction {

	private final PluginTool tool;

	SelectBackRefsAction(PluginTool tool, String owner) {
		super("Back Refs", owner);
		this.tool = tool;

		String group = "references";
		setMenuBarData( new MenuData( new String[] {"Select", "Back Refs"}, null, group ) );
		
		setKeyBindingData( new KeyBindingData(KeyEvent.VK_SEMICOLON, InputEvent.CTRL_MASK ) );
		setHelpLocation(new HelpLocation(HelpTopics.SELECTION, "Backward"));
		addToWindowWhen(NavigatableActionContext.class);
	}
	
	@Override
	protected boolean isEnabledForContext(NavigatableActionContext context) {
		return context.getAddress() != null || context.hasSelection();
	}
	/**
	 * Method called when the action is invoked.
	 * @param ActionEvent details regarding the invocation of this action
	 */
	@Override
    public void actionPerformed(NavigatableActionContext context) {
		AddressSetView addressSet = null;
		
		if (context.hasSelection()) {
			addressSet = context.getSelection();
		} else {
			addressSet = new AddressSet(context.getAddress());
		}
				
		ProgramSelection selection = getSelection(context.getProgram(), addressSet);
		NavigationUtils.setSelection(tool, context.getNavigatable(), selection);
	}

	private ProgramSelection getSelection(Program program, AddressSetView addressSetView){
		AddressSet addressSet = new AddressSet();

		AddressIterator refAddrIter = program.getReferenceManager().getReferenceDestinationIterator(addressSetView,true);
		
		while (refAddrIter.hasNext()) {
			Address reffedAddr = refAddrIter.next();

			ReferenceIterator memRefIter  = program.getReferenceManager().getReferencesTo(reffedAddr);
			while (memRefIter.hasNext()){
				Reference memRef = memRefIter.next();
				Address addr = memRef.getFromAddress();
				if ( addr.isMemoryAddress() ) {
				    addressSet.addRange(addr,addr);
				}
			}
		}	
		return new ProgramSelection(addressSet);	
	}
}
