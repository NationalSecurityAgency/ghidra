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
package ghidra.app.plugin.core.memory;

import javax.swing.event.ChangeListener;

import ghidra.app.cmd.memory.AddMemoryBlockCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.NamingUtilities;
import ghidra.util.datastruct.StringKeyIndexer;

/**
 *
 * Model to manage adding a memory block.
 *
 */
class AddBlockModel {

	private PluginTool tool;
	private Program program;
	private StringKeyIndexer nameIndexer;

	private String blockName;
	private Address startAddr;
	private Address baseAddr;
	private int length;
	private MemoryBlockType blockType;
	private int initialValue;
	private String message;
	private ChangeListener listener;
	private boolean isValid;
	private boolean readEnabled;
	private boolean writeEnabled;
	private boolean executeEnabled;
	private boolean volatileEnabled;
	private boolean isInitialized;

	/**
	 * Construct a new model.
	 * @param tool
	 * @param program
	 */
	AddBlockModel(PluginTool tool, Program program) {
		this.tool = tool;
		this.program = program;
		nameIndexer = new StringKeyIndexer();
		loadBlockNames();
		startAddr = program.getImageBase();
		blockType = MemoryBlockType.DEFAULT;
		initialValue = 0;
		readEnabled = true;
		writeEnabled = true;
		executeEnabled = true;
		volatileEnabled = true;
	}

	void setChangeListener(ChangeListener listener) {
		this.listener = listener;
	}

	void setBlockName(String name) {
		blockName = name;
		validateInfo();
		listener.stateChanged(null);
	}

	void setStartAddress(Address addr) {
		startAddr = addr;
		validateInfo();
		listener.stateChanged(null);
	}

	void setLength(int length) {
		this.length = length;
		validateInfo();
		listener.stateChanged(null);
	}

	void setInitialValue(int initialValue) {
		this.initialValue = initialValue;
		validateInfo();
		listener.stateChanged(null);
	}

	void setBlockType(MemoryBlockType blockType) {
		this.blockType = blockType;
		readEnabled = true;
		writeEnabled = true;
		executeEnabled = true;
		volatileEnabled = true;
		validateInfo();
		listener.stateChanged(null);
	}

	void setIsInitialized(boolean isInitialized) {
		this.isInitialized = isInitialized;
	}

	void setBaseAddress(Address baseAddr) {
		this.baseAddr = baseAddr;
		validateInfo();
		listener.stateChanged(null);
	}

	Address getStartAddress() {
		return startAddr;
	}

	MemoryBlockType getBlockType() {
		return blockType;
	}

	int getInitialValue() {
		return initialValue;
	}

	boolean isValidInfo() {
		return isValid;
	}

	String getMessage() {
		return message;
	}

	Program getProgram() {
		return program;
	}

	boolean isReadEnabled() {
		return readEnabled;
	}

	boolean isWriteEnabled() {
		return writeEnabled;
	}

	boolean isExecuteEnabled() {
		return executeEnabled;
	}

	boolean isVolatileEnabled() {
		return volatileEnabled;
	}

	boolean getInitializedState() {
		return isInitialized;
	}

	/**
	 * Add the block.
	 * @param comment block comment
	 * @param isRead read permissions
	 * @param isWrite write permissions
	 * @param isExecute execute permissions
	 * @param isVolatile volatile setting
	 * @return true if the block was successfully added
	 */
	boolean execute(String comment, boolean isRead, boolean isWrite, boolean isExecute,
			boolean isVolatile) {

		validateInfo();
		if (!isValid) {
			return false;
		}
		AddMemoryBlockCmd cmd = new AddMemoryBlockCmd(blockName, comment, "- none -", startAddr,
			length, isRead, isWrite, isExecute, isVolatile, (byte) initialValue, blockType,
			baseAddr, isInitialized);
		if (!tool.execute(cmd, program)) {
			message = cmd.getStatusMsg();
			return false;
		}
		return true;
	}

	void dispose() {
		tool = null;
		program = null;
	}

	private void validateInfo() {

		message = "";
		isValid = false;
		if (initialValue < 0 && isInitialized) {
			message = "Please enter a valid initial byte value";
			return;
		}
		if (blockName == null || blockName.length() == 0) {
			message = "Please enter a name";
			return;
		}
		if (nameExists(blockName)) {
			message = "Block name already exists";
			return;
		}
		if (!NamingUtilities.isValidName(blockName)) {
			message = "Block name is invalid";
			return;
		}
		if (startAddr == null) {
			message = "Please enter a valid starting address";
			return;
		}
		if (blockType == MemoryBlockType.BIT_MAPPED || blockType == MemoryBlockType.BYTE_MAPPED) {
			isInitialized = false;
			if (baseAddr == null) {
				String blockTypeStr = (blockType == MemoryBlockType.BIT_MAPPED) ? "bit" : "overlay";
				message = "Please enter a source address for the " + blockTypeStr + " block";
				return;
			}
		}
		long sizeLimit =
			isInitialized ? Memory.MAX_INITIALIZED_BLOCK_SIZE : Memory.MAX_UNINITIALIZED_BLOCK_SIZE;
		if (length <= 0 || length > sizeLimit) {
			message = "Please enter a valid length > 0 and <= 0x" + Long.toHexString(sizeLimit);
			return;
		}
		if (blockType == MemoryBlockType.OVERLAY) {
			AddressFactory factory = program.getAddressFactory();
			AddressSpace[] spaces = factory.getAddressSpaces();
			for (int i = 0; i < spaces.length; i++) {
				if (spaces[i].getName().equals(blockName)) {
					message = "Address Space named " + blockName + " already exists";
					return;
				}
			}
		}
		isValid = true;
	}

	/**
	 * Return true if the name exists in the name table.
	 */
	private boolean nameExists(String name) {
		return nameIndexer.get(name) >= 0;
	}

	/**
	 * Load the block names into the name table.
	 */
	private void loadBlockNames() {
		Memory memory = program.getMemory();

		MemoryBlock[] blocks = memory.getBlocks();
		for (int i = 0; i < blocks.length; i++) {
			nameIndexer.put(blocks[i].getName());
		}
	}

}
