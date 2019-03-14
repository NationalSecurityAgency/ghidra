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
package ghidra.app.plugin.core.fallthrough;

import ghidra.app.cmd.refs.ClearFallThroughCmd;
import ghidra.app.cmd.refs.SetFallThroughCmd;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * This class is really a model for the FallThroughDialog state.  However, it is used as a 
 * convenience for executing the auto-override and clear-fallthrough actions.
 */
class FallThroughModel implements ChangeListener {
	private PluginTool tool;
	private Program program;
	private Address currentAddr;
	private Address currentFallthroughAddr;
	private Address defaultFallthroughAddr;
	private ChangeListener listener;
	private boolean isDefault;
	private boolean isUserDefined;
	private String message="";
	private boolean executingCommand;
	private BrowserCodeUnitFormat cuFormat;
		
	/**
	 * Constructor for FallThroughModel.
	 */
	FallThroughModel(PluginTool tool, Program program, Address address) {
		this.program = program;
		this.tool = tool;
		listener = this;	// dummy listener so we don't have to check for null;
		cuFormat = new BrowserCodeUnitFormat(tool);
		setHomeAddress(address);
	}

	/**
	 * Set the change listener.
	 */
	void setChangeListener(ChangeListener listener) {
		this.listener = listener;
	}
	/**
	 * Set the current address
	 * @param inst instruction whose fallthrough may be changed
	 */
	void setHomeAddress(Address address) {
		Instruction inst = program.getListing().getInstructionAt(address);
		if (inst == null) {
			return;
		}
		currentAddr = inst.getMinAddress();
		currentFallthroughAddr = inst.getFallThrough();
		defaultFallthroughAddr = inst.getDefaultFallThrough();
		isUserDefined = inst.isFallThroughOverridden();
		isDefault = !isUserDefined;
		listener.stateChanged(null);
	}
	/**
	 * 
	 * Get the current address for the instruction whose fallthough
	 * may change.
	 */
	Address getAddress() {
		if (currentAddr != null &&
			program.getListing().getInstructionContaining(currentAddr) == null) {
			currentAddr = null;
		}
		return currentAddr;
	}
	/**
	 * Get the current fallthrough address.
	 * @return
	 */
	Address getCurrentFallthrough() {
		return currentFallthroughAddr;
	}
	/**
	 * Set the current fallthrough address.
	 */
	void setCurrentFallthrough(Address addr) {
		if (isUserDefined && !executingCommand) {
			currentFallthroughAddr = addr;
			listener.stateChanged(null);
		}
	}
	/**
	 * The option for "use default" fallthrough was chosen.
	 *
	 */
	void defaultSelected() {
		isDefault = true; 
		isUserDefined = false;
		currentFallthroughAddr = defaultFallthroughAddr;
		listener.stateChanged(null);
	}
	/**
	 * The option for the "user defined" fallthrough was chosen.
	 *
	 */
	void userSelected() {
		isDefault = false;
		isUserDefined = true;
		currentFallthroughAddr = null;
		listener.stateChanged(null);
	}				
	boolean isDefaultFallthrough() {
		return isDefault;
	}
	boolean isUserDefinedFallthrough() {
		return isUserDefined;
	}

	boolean allowAddressEdits() {
		return isUserDefined;
	}
	boolean isValidInput() {
//		if (isUserDefined && currentFallthroughAddr == null) {
//			Instruction inst = program.getListing().getInstructionContaining(currentAddr);
//			if (inst.getFallThrough() != null) {
//				return false;
//			}
//		}
		return true;
	}		
	String getMessage() {
		String msg = message;
		message = "";
		return msg;
	}
	String getInstructionRepresentation() {
		Instruction inst = program.getListing().getInstructionContaining(currentAddr);
		return cuFormat.getRepresentationString(inst);
	}
	/**
	 * Execute the command to set the fall-through.
	 * @return true if the input was valid
	 */		
	boolean execute() {
		message = "";
		Instruction inst = program.getListing().getInstructionContaining(currentAddr);
		Address ftAddr = inst.getFallThrough();
		if (ftAddr == null ||
			!inst.getFallThrough().equals(currentFallthroughAddr)) {
			executingCommand = true;
			SetFallThroughCmd cmd = new SetFallThroughCmd(inst.getMinAddress(), 
														currentFallthroughAddr);
			tool.execute(cmd, program);
			message = "Updated Fallthrough address";
			executingCommand = false;
			if (defaultFallthroughAddr != null && 
				defaultFallthroughAddr.equals(currentFallthroughAddr)) {
				isDefault = true;
				isUserDefined = false;					
			}
		}
		else {
			message = "No changes were made";
		}
		listener.stateChanged(null);
		return true;
	}
	
	
	/**
	 * Method autoOverride.
	 * @param currentSelection
	 */
	void autoOverride(AddressSetView view) {
		CompoundCmd cmd = new CompoundCmd("Auto-Override");
		AddressRangeIterator iter = view.getAddressRanges();
		while (iter.hasNext()) {
			override(iter.next(), cmd);
		}
		if (cmd.size() > 0) {
			if (!tool.execute(cmd, program)) {
				tool.setStatusInfo(cmd.getStatusMsg());
			}
		}
	}

	void clearOverride(AddressSetView view) {
		CompoundCmd cmd = new CompoundCmd("Clear FallThroughs");
		InstructionIterator it = program.getListing().getInstructions(view, true);
		while(it.hasNext()) {
			Instruction inst = it.next();
			if (inst.isFallThroughOverridden()) {
				cmd.add(new ClearFallThroughCmd(inst.getMinAddress()));
			}
		}
		if (cmd.size() > 0) {
			tool.execute(cmd, program);
		}
	}
	/**
	 * Method dispose.
	 */
	void dispose() {
		program = null;
		tool = null;
		listener = null;
	}
	 
	Program getProgram() {
		return program;
	}
	
	private void override(AddressRange range, CompoundCmd cmd) {
		Address min = range.getMinAddress();
		Address max = range.getMaxAddress();
		Listing listing = program.getListing();
		Instruction inst = listing.getInstructionAt(min);
		if (inst == null) {
			inst = listing.getInstructionAfter(min);
		}
		while (inst != null && inst.getMinAddress().compareTo(max) <= 0) {
			
			Data data = listing.getDataAfter(inst.getMinAddress());
			if (data == null) {
				return;
			}
			inst = listing.getInstructionBefore(data.getMinAddress());
			if (inst.getFallThrough() != null &&
				range.contains(inst.getMinAddress())) {
				setFallThrough(inst.getMinAddress(), cmd);
			}
			inst = listing.getInstructionAfter(data.getMinAddress());
		}
	} 
	
	private void setFallThrough(Address addr, CompoundCmd cmd) {
		Instruction inst = program.getListing().getInstructionAfter(addr);
		if (inst != null) {
			cmd.add(new SetFallThroughCmd(addr, inst.getMinAddress()));
		}
	}

	public void stateChanged(ChangeEvent e) {
		// do nothing - just a placeholder so that we don't have to check for null listener
	}
}
