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
import ghidra.program.model.listing.Program;

/**
 *
 * Model to manage the values for expanding a block up. 
 * 
 */
class ExpandBlockUpModel extends ExpandBlockModel {
	
	/**
	 * 
	 * Constructor
	 * @param tool tool needed for the edits
	 * @param program affected program
	 */
	ExpandBlockUpModel(PluginTool tool, Program program) {
		super(tool, program);
	}
	/**
	 * 
	 * @see ghidra.app.plugin.core.memory.ExpandBlockModel#setStartAddress(ghidra.program.model.address.Address)
	 */
	@Override
    void setStartAddress(Address addr) {
		message = "";
		startAddr = addr;
		
		if (startAddr == null) {
			message = "Invalid Address";
		}

		else if (startAddr.compareTo(block.getStart()) >= 0) {
			message = "Start must be less than " +  
						  block.getStart();
		}
		else {
			length = block.getEnd().subtract(startAddr) +1;
		}
		listener.stateChanged(null);		
	}
	/**
	 * This method is not implemented; 
	 * can't set the end address for expanding up.
	 */
	@Override
    void setEndAddress(Address addr) {
	}
	/**
	 * 
	 * @see ghidra.app.plugin.core.memory.ExpandBlockModel#setLength(int)
	 */
	@Override
    void setLength(long length) {
		message = "";
		
		this.length = length;
		if (isValidLength()) { 
			try {
				startAddr = block.getEnd().subtractNoWrap(length-1);
			} catch (Exception e) {
				message = "Expanded block is too large";
			}
		}
		listener.stateChanged(null);
	}
	/**
	 * Expand the block.
	 * @return true if the block was expanded successfully
	 */
	@Override
    boolean execute() {
		message="";
		try {
			length = block.getStart().subtract(startAddr);
			if (length == 0) {
				return true;
			}
			if (length != block.getSize() ||
				startAddr.compareTo(block.getStart()) != 0) {
				return expandBlock();
			}
		} catch(Exception e) {
			message = e.getMessage();
			if (message  == null) {
				message = e.toString();
			}
		}
		return false;
	}
}
