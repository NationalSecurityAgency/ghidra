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
package ghidra.app.plugin.core.memory;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;

/**
 * Model to expand a block and extend its ending address.
 * 
 * 
 */
class ExpandBlockDownModel extends ExpandBlockModel {

	/**
	 * Constructor
	 * @param tool tool needed for the edits
	 * @param program affected program
	 */
	public ExpandBlockDownModel(PluginTool tool, Program program) {
		super(tool, program);
	}


	/**
	 * @see ghidra.app.plugin.core.memory.ExpandBlockModel#execute()
	 */
	@Override
    boolean execute() {
		message = "";

		// get the start for what will be the start of a
		// tempory block
		length = endAddr.subtract(block.getEnd());
		if (length == 0) {
			return true;
		}
		try {
			startAddr = endAddr.subtract(length-1); 
			return expandBlock();
		} catch(Exception e) {
			message = e.getMessage();
			if (message  == null) {
				message = e.toString();
			}
		}
		return false;
	}

	/**
	 * @see ghidra.app.plugin.core.memory.ExpandBlockModel#setLength(int)
	 */
	@Override
    void setLength(long length) {
		message = "";
		this.length = length;
		if (isValidLength()) {
			try {
				endAddr = block.getStart().addNoWrap(length-1);
			} catch(AddressOverflowException e) {
				message = "Expanded block is too large";
			}
		}
		listener.stateChanged(null);	

	}

	/**
	 * @see ghidra.app.plugin.core.memory.ExpandBlockModel#setStartAddress(ghidra.program.model.address.Address)
	 */
	@Override
    void setEndAddress(Address addr) {
		message="";
		endAddr = addr;
		
		if (endAddr == null) {
			message = "Invalid Address";
		}
		else if (block.getEnd().compareTo(endAddr) >= 0) {
			message = "End must be greater than " +
							block.getEnd();
		}
		else {
			length = endAddr.subtract(block.getStart()) +1;	
		}
		listener.stateChanged(null);
	}
	@Override
    void setStartAddress(Address addr) {
	}
	
}
