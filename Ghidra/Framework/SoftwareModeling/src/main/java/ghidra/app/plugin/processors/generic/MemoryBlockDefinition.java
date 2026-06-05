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
package ghidra.app.plugin.processors.generic;

import java.util.List;

import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlAttributeException;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;

/**
 * {@link MemoryBlockDefinition} provides a default memory block specification.
 */
public class MemoryBlockDefinition {

	private final String blockName;
	private final String addressString;
	private final int length;
	private final boolean initialized;
	private final boolean overlay;
	private final String bitMappedAddress;
	private final String byteMappedAddress;
	private final ByteMappingScheme byteMappingScheme;

	private final String mode;
	private final boolean readPermission;
	private final boolean writePermission;
	private final boolean executePermission;
	private final boolean isVolatile;

	private static final String DEFAULT_MODE = "rw";

	/**
	 * Construct <code>MemoryBlockDefinition</code> using a text-based specified.
	 * Intended for use when parsing XML.
	 * @param blockName memory block name (required)
	 * @param addressString start of memory block (required, see {@link AddressFactory#getAddress(String)}).
	 * @param bitMappedAddress optional specification of data source address for bit-mapped memory
	 * block (may be null)
	 * @param byteMappedAddressRatio optional specification of data source address for byte-mapped 
	 * memory block which may include optional byte mapping ratio, e.g., "rom:1000/2:4" (may be 
	 * null).  The default mapping ratio is 1-byte to 1-source-byte (1:1), although other 
	 * decimations may be specified using a mapping ratio. When specifying a mapping ratio both 
	 * values must be in the range 1..127 where the right (source-byte count) value must be 
	 * greater-than-or-equal to the left value (e.g., 2:4).
	 * @param mode block mode as concatenation of the following mode indicator characters.  If null
	 * the default mode (rw) will be used.
	 * <pre>
	 *   r - read mode enabled
	 *   w - write mode enabled
	 *   x - execute mode enabled
	 *   v - volatile mode enabled
	 * </pre>
	 * @param lengthString length of memory block in bytes (required)
	 * @param initializedString boolean (y | n | true | false) indicating if memory block is
	 * initialialized or not (ignored for mapped block specification)
	 * @param overlayString boolean (y | n | true | false) indicating if memory block is an overlay
	 * (false assumed if null).
	 * @throws XmlAttributeException if parse failure occurs (NOTE: address parsing is not performed)
	 */
	private MemoryBlockDefinition(String blockName, String addressString, String bitMappedAddress,
			String byteMappedAddressRatio, String mode, String lengthString,
			String initializedString, String overlayString) throws XmlAttributeException {

		this.mode = mode != null ? mode.toLowerCase() : DEFAULT_MODE;

		// Parse specified access mode
		readPermission = this.mode.indexOf('r') >= 0;
		writePermission = this.mode.indexOf('w') >= 0;
		executePermission = this.mode.indexOf('x') >= 0;
		isVolatile = this.mode.indexOf('v') >= 0;

		if (blockName == null) {
			throw new XmlAttributeException("Missing default memory block 'name'");
		}
		this.blockName = blockName;

		if (addressString == null) {
			throw new XmlAttributeException("Missing default memory block 'start_address'");
		}
		this.addressString = addressString;

		this.bitMappedAddress = bitMappedAddress;

		if (byteMappedAddressRatio != null) {
			if (bitMappedAddress != null) {
				throw new XmlAttributeException(
					"may not specify both bit_mapped_address and byte_mapped_address");
			}
			int index = byteMappedAddressRatio.indexOf('/');
			if (index > 0) {
				byteMappingScheme =
					new ByteMappingScheme(byteMappedAddressRatio.substring(index + 1));
				byteMappedAddress = byteMappedAddressRatio.substring(0, index);
			}
			else {
				// 1:1 mapping scheme assumed (null byteMappingScheme)
				byteMappingScheme = null;
				byteMappedAddress = byteMappedAddressRatio;
			}
		}
		else {
			byteMappedAddress = null;
			byteMappingScheme = null;
		}

		// Parse specified length string
		int parsedLen = -1;
		try {
			parsedLen = XmlUtilities.parseInt(lengthString);
		}
		catch (NumberFormatException e) {
			// ignore - length will be checked below
		}
		if (parsedLen <= 0) {
			throw new XmlAttributeException(lengthString + " is not a valid 'length'");
		}
		length = parsedLen;

		if (initializedString != null) {
			if (bitMappedAddress != null || byteMappedAddress != null) {
				throw new XmlAttributeException(
					"mapped block specifications must not specify initialized attribute");
			}
		}
		initialized = XmlUtilities.parseBoolean(initializedString);
		overlay = XmlUtilities.parseBoolean(overlayString);
	}

	public MemoryBlockDefinition(XmlElement element) throws XmlAttributeException {
		this(element.getAttribute("name"), element.getAttribute("start_address"),
			element.getAttribute("bit_mapped_address"), element.getAttribute("byte_mapped_address"),
			element.getAttribute("mode"), element.getAttribute("length"),
			element.getAttribute("initialized"), element.getAttribute("overlay"));
	}

	private static Address parseAddress(String addressString, Program program, String description)
			throws InvalidAddressException {
		Address addr = XmlProgramUtilities.parseAddress(program.getAddressFactory(), addressString);
		if (addr == null) {
			throw new InvalidAddressException(
				"Invalid " + description + " in memory block definition: " + addressString);
		}
		return addr;
	}

	/**
	 * {@return memory block name}
	 */
	public String getBlockName() {
		return blockName;
	}

	/**
	 * Create or fixup existing block found within specified program.
	 * @param program target program
	 * @return new or adjusted memory block
	 * @throws LockException if program does not have exclusive access
	 * @throws MemoryBlockException if failed to create or fixup default memory block
	 */
	public MemoryBlock fixupBlock(ProgramDB program) throws LockException, MemoryBlockException {

		program.checkExclusiveAccess();

		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(blockName);
		if (block == null) {
			try {
				Msg.info(this, "Adding process-defined memory block: " + blockName);
				return createBlock(program);
			}
			catch (MemoryConflictException | AddressOverflowException | InvalidAddressException e) {
				throw new MemoryBlockException("Create block failed", e);
			}
		}

		MemoryBlockType blockType = getBlockType();
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();

		if (!blockType.equals(block.getType()) || overlay != block.isOverlay() ||
			sourceInfos.size() != 1) {
			throw new MemoryBlockException("Incompatible memory block type");
		}

		MemoryBlockSourceInfo sourceInfo = sourceInfos.get(0);

		Address addr;
		Address currentStartAddress;
		try {
			addr = parseAddress(addressString, program, "block address");

			currentStartAddress = block.getStart();
			AddressSpace currentAddressSpace = currentStartAddress.getAddressSpace();

			if (currentAddressSpace instanceof OverlayAddressSpace overlaySpace) {
				if (overlaySpace.getOverlayedSpace().equals(addr.getAddressSpace())) {
					throw new MemoryBlockException("Incompatible overlay memory block");
				}
				// Redefine overlay block start address for comparison use
				addr = overlaySpace.getAddressInThisSpaceOnly(addr.getOffset());
			}

			if (bitMappedAddress != null) {
				Address mappedAddr = parseAddress(bitMappedAddress, program, "bit-mapped address");
				if (addr.equals(currentStartAddress) && sourceInfo.getMappedRange().isPresent() &&
					mappedAddr.equals(sourceInfo.getMappedRange().get().getMinAddress()) &&
					length == block.getSize()) {
					return block;
				}
				// We do not currently support modifying default bit-mapped block
				throw new MemoryBlockException("inconsistent bit-mapped block");
			}
			else if (byteMappedAddress != null) {
				Address mappedAddr =
					parseAddress(byteMappedAddress, program, "byte-mapped address");
				if (addr.equals(currentStartAddress) && sourceInfo.getMappedRange().isPresent() &&
					mappedAddr.equals(sourceInfo.getMappedRange().get().getMinAddress()) &&
					length == block.getSize()) {
					return block;
				}
				// We do not currently support modifying default byte-mapped block
				throw new MemoryBlockException("inconsistent byte-mapped block");
			}
		}
		catch (InvalidAddressException e) {
			throw new MemoryBlockException("failed to process processor block address", e);
		}

		if (sourceInfo.getFileBytes().isPresent() || sourceInfo.getMappedRange().isPresent()) {
			throw new MemoryBlockException("unsupported file or memory-mapped block");
		}

		if (!addr.equals(currentStartAddress)) {
			throw new MemoryBlockException(
				"inconsistent block start address: " + addr + " / " + currentStartAddress);
		}

		try {
			if (length > block.getSize()) {
				// Expand processor defined memory block
				Msg.info(this, "Expanding processor defined memory block from " + block.getSize() +
					"-bytes to " + length + "-bytes: " + blockName);
				MemoryBlock newBlock = memory.createBlock(block, block.getName() + ".exp",
					block.getEnd().next(), length - block.getSize());
				MemoryBlock b = memory.join(block, newBlock);
				if (!b.getName().equals(blockName)) {
					b.setName(blockName); // preserve block name
				}
			}
			else {
				Msg.warn(this, "Ignored processor block size reduction: " + blockName);
			}

			boolean accessAdjusted = false;
			if (readPermission != block.isRead()) {
				block.setRead(readPermission);
				accessAdjusted = true;
			}
			if (writePermission != block.isWrite()) {
				block.setWrite(writePermission);
				accessAdjusted = true;
			}
			if (executePermission != block.isExecute()) {
				block.setExecute(executePermission);
				accessAdjusted = true;
			}
			if (isVolatile != block.isVolatile()) {
				block.setVolatile(isVolatile);
				accessAdjusted = true;
			}
			if (accessAdjusted) {
				Msg.warn(this, "Updated processor block access mode (" + mode + "): " + blockName);
			}

		}
		catch (IllegalArgumentException | MemoryConflictException | AddressOverflowException e) {
			throw new MemoryBlockException("block adjustment failed", e);
		}

		return block;
	}

	private MemoryBlockType getBlockType() {
		if (bitMappedAddress != null) {
			return MemoryBlockType.BIT_MAPPED;
		}
		if (byteMappedAddress != null) {
			return MemoryBlockType.BYTE_MAPPED;
		}
		return MemoryBlockType.DEFAULT;
	}

	/**
	 * Create memory block within specified program based upon this block specification.
	 * @param program target program
	 * @return newly created memory block
	 * @throws LockException if program does not have exclusive access required when adding memory blocks.
	 * @throws MemoryConflictException if this specification conflicts with an existing memory block in program
	 * @throws AddressOverflowException if memory space constraints are violated by block specification
	 * @throws InvalidAddressException if address defined by this block specification is invalid
	 * for the specified program.  May also indicate an improperly formatted address attribute.
	 */
	public MemoryBlock createBlock(Program program) throws LockException, MemoryConflictException,
			AddressOverflowException, InvalidAddressException {

		Memory mem = program.getMemory();
		Address addr = parseAddress(addressString, program, "block address");

		MemoryBlock block;
		if (bitMappedAddress != null) {
			Address mappedAddr = parseAddress(bitMappedAddress, program, "bit-mapped address");
			block = mem.createBitMappedBlock(blockName, addr, mappedAddr, length, overlay);
		}
		else if (byteMappedAddress != null) {
			Address mappedAddr = parseAddress(byteMappedAddress, program, "byte-mapped address");
			block = mem.createByteMappedBlock(blockName, addr, mappedAddr, length,
				byteMappingScheme, overlay);
		}
		else if (initialized) {
			try {
				block = mem.createInitializedBlock(blockName, addr, length, (byte) 0,
					TaskMonitor.DUMMY, overlay);
			}
			catch (CancelledException e) {
				throw new AssertException(e); // unexpected
			}
		}
		else {
			block = mem.createUninitializedBlock(blockName, addr, length, overlay);
		}
		block.setRead(readPermission);
		block.setWrite(writePermission);
		block.setExecute(executePermission);
		block.setVolatile(isVolatile);
		return block;
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder(blockName);
		buf.append(':');
		if (overlay) {
			buf.append("overlay");
		}
		buf.append(" start_address=");
		buf.append(addressString);
		if (initialized) {
			buf.append(", initialized ");
		}
		else if (bitMappedAddress != null) {
			buf.append(", bit_mapped_address=");
			buf.append(bitMappedAddress);
		}
		else if (byteMappedAddress != null) {
			buf.append(", byte_mapped_address=");
			buf.append(byteMappedAddress);
			if (byteMappingScheme != null) {
				buf.append('/');
				buf.append(byteMappingScheme.toString());
			}
		}
		else {
			buf.append(", uninitialized");
		}
		buf.append(", length=0x");
		buf.append(Integer.toHexString(length));
		return buf.toString();
	}

}
