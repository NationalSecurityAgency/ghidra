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

import ghidra.app.cmd.memory.*;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.datastruct.StringKeyIndexer;
import ghidra.util.exception.AssertException;

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
	private int schemeDestByteCount;
	private int schemeSrcByteCount;
	private long length;
	private MemoryBlockType blockType;
	private boolean isOverlay;
	private int initialValue;
	private String message;
	private ChangeListener listener;
	private boolean isValid;
	private boolean isRead;
	private boolean isWrite;
	private boolean isExecute;
	private boolean isVolatile;
	private InitializedType initializedType;
	private String comment;
	private FileBytes fileBytes;
	private long fileBytesOffset = -1;

	enum InitializedType {
		UNITIALIZED, INITIALIZED_FROM_VALUE, INITIALIZED_FROM_FILE_BYTES;
	}

	AddBlockModel(PluginTool tool, Program program) {
		this.tool = tool;
		this.program = program;
		nameIndexer = new StringKeyIndexer();
		loadBlockNames();
		startAddr = program.getImageBase();
		blockType = MemoryBlockType.DEFAULT;
		initialValue = 0;
	}

	void setChangeListener(ChangeListener listener) {
		this.listener = listener;
	}

	void setBlockName(String name) {
		blockName = name;
		validateInfo();
		listener.stateChanged(null);
	}

	public void setComment(String comment) {
		this.comment = comment;
	}

	void setStartAddress(Address addr) {
		startAddr = addr;
		validateInfo();
		listener.stateChanged(null);
	}

	void setLength(long length) {
		this.length = length;
		validateInfo();
		listener.stateChanged(null);
	}

	void setFileOffset(long fileOffset) {
		this.fileBytesOffset = fileOffset;
		validateInfo();
		listener.stateChanged(null);
	}

	void setFileBytes(FileBytes fileBytes) {
		this.fileBytes = fileBytes;
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
		isRead = true;
		isWrite = true;
		isExecute = false;
		isVolatile = false;
		isOverlay = false;
		schemeDestByteCount = blockType == MemoryBlockType.BIT_MAPPED ? 8 : 1;
		schemeSrcByteCount = 1;
		initializedType = InitializedType.UNITIALIZED;
		validateInfo();
		listener.stateChanged(null);
	}

	void setRead(boolean b) {
		this.isRead = b;
	}

	void setWrite(boolean b) {
		this.isWrite = b;
	}

	void setExecute(boolean b) {
		this.isExecute = b;
	}

	void setVolatile(boolean b) {
		this.isVolatile = b;
	}

	void setOverlay(boolean b) {
		this.isOverlay = b;
		validateInfo();
		listener.stateChanged(null);
	}

	void setInitializedType(InitializedType type) {
		this.initializedType = type;
		validateInfo();
		listener.stateChanged(null);
	}

	void setBaseAddress(Address baseAddr) {
		this.baseAddr = baseAddr;
		validateInfo();
		listener.stateChanged(null);
	}

	void setSchemeSrcByteCount(int value) {
		this.schemeSrcByteCount = value;
		validateInfo();
		listener.stateChanged(null);
	}

	int getSchemeSrcByteCount() {
		return schemeSrcByteCount;
	}

	void setSchemeDestByteCount(int value) {
		this.schemeDestByteCount = value;
		validateInfo();
		listener.stateChanged(null);
	}

	int getSchemeDestByteCount() {
		return schemeDestByteCount;
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

	boolean isRead() {
		return isRead;
	}

	boolean isWrite() {
		return isWrite;
	}

	boolean isExecute() {
		return isExecute;
	}

	boolean isVolatile() {
		return isVolatile;
	}

	boolean isOverlay() {
		return isOverlay;
	}

	InitializedType getInitializedType() {
		return initializedType;
	}

	boolean execute() {

		validateInfo();
		if (!isValid) {
			return false;
		}
		Command cmd = createAddBlockCommand();
		if (!tool.execute(cmd, program)) {
			message = cmd.getStatusMsg();
			return false;
		}
		return true;
	}

	Command createAddBlockCommand() {
		String source = "";
		switch (blockType) {
			case BIT_MAPPED:
				return new AddBitMappedMemoryBlockCmd(blockName, comment, source, startAddr, length,
					isRead, isWrite, isExecute, isVolatile, baseAddr, isOverlay);
			case BYTE_MAPPED:
				ByteMappingScheme byteMappingScheme =
					new ByteMappingScheme(schemeDestByteCount, schemeSrcByteCount);
				return new AddByteMappedMemoryBlockCmd(blockName, comment, source, startAddr,
					length, isRead, isWrite, isExecute, isVolatile, baseAddr, byteMappingScheme,
					isOverlay);
			case DEFAULT:
				return createNonMappedMemoryBlock(source);
			default:
				throw new AssertException("Encountered unexpected block type: " + blockType);
		}
	}

	private Command createNonMappedMemoryBlock(String source) {
		switch (initializedType) {
			case INITIALIZED_FROM_FILE_BYTES:
				return new AddFileBytesMemoryBlockCmd(blockName, comment, source, startAddr, length,
					isRead, isWrite, isExecute, isVolatile, fileBytes, fileBytesOffset, isOverlay);
			case INITIALIZED_FROM_VALUE:
				return new AddInitializedMemoryBlockCmd(blockName, comment, source, startAddr,
					length, isRead, isWrite, isExecute, isVolatile, (byte) initialValue, isOverlay);
			case UNITIALIZED:
				return new AddUninitializedMemoryBlockCmd(blockName, comment, source, startAddr,
					length, isRead, isWrite, isExecute, isVolatile, isOverlay);
			default:
				throw new AssertException(
					"Encountered unexpected intialized type: " + initializedType);

		}
	}

	void dispose() {
		tool = null;
		program = null;
	}

	private void validateInfo() {
		message = "";
		isValid = hasValidName() && hasValidStartAddress() && hasValidLength() &&
			hasNoMemoryConflicts() && hasMappedAddressIfNeeded() &&
			hasInitialValueIfNeeded() && hasFileBytesInfoIfNeeded() && isOverlayIfOtherSpace();
	}

	private boolean hasFileBytesInfoIfNeeded() {

		if (initializedType != InitializedType.INITIALIZED_FROM_FILE_BYTES) {
			return true;
		}

		if (fileBytes == null) {
			message = "Please select a FileBytes entry";
			return false;
		}

		if (fileBytesOffset < 0 || fileBytesOffset >= fileBytes.getSize()) {
			message =
				"Please enter a valid file bytes offset (0 - " + (fileBytes.getSize() - 1) + ")";
			return false;
		}

		if (fileBytesOffset + length > fileBytes.getSize()) {
			message = "File bytes offset + length exceeds file bytes size: " + fileBytes.getSize();
			return false;
		}
		return true;
	}

	private boolean hasInitialValueIfNeeded() {

		if (initializedType != InitializedType.INITIALIZED_FROM_VALUE) {
			return true;
		}

		if (initialValue >= 0 && initialValue <= 255) {
			return true;
		}
		message = "Please enter a valid initial byte value";
		return false;
	}

	private boolean isOverlayIfOtherSpace() {
		if (startAddr.getAddressSpace().equals(AddressSpace.OTHER_SPACE)) {
			if (!isOverlay) {
				message = "Blocks defined in the " + AddressSpace.OTHER_SPACE.getName() +
					" space must be overlay blocks";
				return false;
			}
		}
		return true;
	}

	private boolean hasMappedAddressIfNeeded() {
		if (blockType != MemoryBlockType.BIT_MAPPED && blockType != MemoryBlockType.BYTE_MAPPED) {
			return true;
		}
		if (baseAddr == null) {
			message = "Please enter a valid mapped region Source Address";
			return false;
		}

		if (blockType == MemoryBlockType.BYTE_MAPPED) {
			if (schemeDestByteCount <= 0 || schemeDestByteCount > Byte.MAX_VALUE ||
				schemeSrcByteCount <= 0 || schemeSrcByteCount > Byte.MAX_VALUE) {
				message = "Mapping Ratio values must be within range: 1 to 127";
				return false;
			}
			if (schemeDestByteCount > schemeSrcByteCount) {
				message =
					"Mapping Ratio destination byte count (left-value) must be less than or equal the source byte count (right-value)";
				return false;
			}
			try {
				long lastOffset = length - 1;
				long sourceOffset = (schemeSrcByteCount * (lastOffset / schemeDestByteCount)) +
					(lastOffset % schemeDestByteCount);
				baseAddr.addNoWrap(sourceOffset);
			}
			catch (AddressOverflowException e) {
				message =
					"Insufficient space in byte-mapped source region at " + baseAddr.toString(true);
				return false;
			}
		}
		else if (blockType == MemoryBlockType.BIT_MAPPED) {
			try {
				baseAddr.addNoWrap((length - 1) / 8);
			}
			catch (AddressOverflowException e) {
				message =
					"Insufficient space in bit-mapped source region at " + baseAddr.toString(true);
				return false;
			}
		}
		return true;
	}

	private boolean hasNoMemoryConflicts() {
		if (isOverlay) {
			return true;
		}
		Address endAddr = startAddr.add(length - 1);
		AddressSet intersectRange = program.getMemory().intersectRange(startAddr, endAddr);
		if (!intersectRange.isEmpty()) {
			AddressRange firstRange = intersectRange.getFirstRange();
			message = "Block address conflict: " + firstRange;
			return false;
		}
		return true;
	}

	private boolean hasValidLength() {
		long limit = Memory.MAX_BLOCK_SIZE;
		long spaceLimit = startAddr.getAddressSpace().getMaxAddress().subtract(startAddr);
		if (spaceLimit >= 0) {
			limit = Math.min(limit, spaceLimit + 1);
		}
		if (length > 0 && length <= limit) {
			return true;
		}
		message = "Please enter a valid Length: 1 to 0x" + Long.toHexString(limit);
		return false;
	}

	private boolean hasValidStartAddress() {
		if (startAddr != null) {
			return true;
		}
		message = "Please enter a valid Start Address";
		return false;
	}

	private boolean hasValidName() {
		if (blockName == null || blockName.length() == 0) {
			message = "Please enter a Block Name";
			return false;
		}
		if (!Memory.isValidMemoryBlockName(blockName)) {
			message = "Block Name is invalid";
			return false;
		}
		if (nameExists(blockName)) {
			message = "Warning! Duplicate Block Name";
		}
		return true;
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
		for (MemoryBlock block : blocks) {
			nameIndexer.put(block.getName());
		}
	}

}
