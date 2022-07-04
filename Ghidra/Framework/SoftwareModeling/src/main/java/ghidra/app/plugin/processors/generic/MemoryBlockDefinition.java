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

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlAttributeException;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;

/**
 * 
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class MemoryBlockDefinition {

	private String blockName;
	private String addressString;
	private int length;
	private boolean initialized;
	private boolean overlay;
	private String bitMappedAddress;
	private String byteMappedAddress;
	private ByteMappingScheme byteMappingScheme;
	private boolean readPermission = true;
	private boolean writePermission = true;
	private boolean executePermission = false;
	private boolean volatilePermission = false;

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
	 * @param mode block mode as concatenation of the following mode indicator characters:
	 * <pre>
	 *   r - read mode enabled
	 *   w - write mode enabled
	 *   x - execute mode enabled
	 *   v - volatile mode enabled
	 * </pre>
	 * @param lengthString length of memory block in bytes (required)
	 * @param initializedString boolean (y | n | true | false) indicating if memory block is
	 * initialialized or not (must be null for mapped block specification)
	 * @param overlayString boolean (y | n | true | false) indicating if memory block is an overlay
	 * (false assumed if null).
	 * @throws XmlAttributeException if parse failure occurs (NOTE: address parsing is not performed)
	 */
	private MemoryBlockDefinition(String blockName, String addressString, String bitMappedAddress,
			String byteMappedAddressRatio, String mode, String lengthString,
			String initializedString, String overlayString)
			throws XmlAttributeException {

		this.blockName = blockName;
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
				byteMappedAddress = byteMappedAddressRatio;
			}
		}

		if (mode != null) {
			mode = mode.toLowerCase();
			readPermission = mode.indexOf('r') >= 0;
			writePermission = mode.indexOf('w') >= 0;
			executePermission = mode.indexOf('x') >= 0;
			volatilePermission = mode.indexOf('v') >= 0;
		}
		try {
			length = XmlUtilities.parseInt(lengthString);
		}
		catch (NumberFormatException e) {
			throw new XmlAttributeException(lengthString + " is not a valid integer");
		}
		if (initializedString != null) {
			if (bitMappedAddress != null || byteMappedAddress != null) {
				throw new XmlAttributeException(
					"mapped block specifications must not specify initialized attribute");
			}
			initialized = XmlUtilities.parseBoolean(initializedString);
		}
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
	 * Create memory block within specified program based upon this block specification.
	 * @param program target program
	 * @throws LockException if program does not have exclusive access required when adding memory blocks.
	 * @throws MemoryConflictException if this specification conflicts with an existing memory block in program
	 * @throws AddressOverflowException if memory space constraints are violated by block specification
	 * @throws InvalidAddressException if address defined by this block specification is invalid
	 * for the specified program.  May also indicate an improperly formatted address attribute.
	 */
	public void createBlock(Program program) throws LockException, MemoryConflictException,
			AddressOverflowException, InvalidAddressException {
		if (blockName == null || addressString == null || length <= 0) {
			return;
		}

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
				block =
					mem.createInitializedBlock(blockName, addr, length, (byte) 0,
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
		block.setVolatile(volatilePermission);
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
