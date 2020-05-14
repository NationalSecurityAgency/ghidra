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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.*;
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
	private String bitMappedAddress;
	private boolean readPermission = true;
	private boolean writePermission = true;
	private boolean executePermission = false;
	private boolean volatilePermission = false;

	@Override
	public String toString() {
		return blockName + " @ " + addressString + ", length=0x" + Integer.toHexString(length);
	}

	public MemoryBlockDefinition(String blockName, String addressString, String bitMappedAddress,
			String mode, String lengthString, String initializedString)
			throws XmlAttributeException {
		this.blockName = blockName;
		this.addressString = addressString;
		this.bitMappedAddress = bitMappedAddress;
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
		initialized = XmlUtilities.parseBoolean(initializedString);
	}

	public MemoryBlockDefinition(XmlElement element) {
		this(element.getAttribute("name"), element.getAttribute("start_address"),
			element.getAttribute("bit_mapped_address"), element.getAttribute("mode"),
			element.getAttribute("length"), element.getAttribute("initialized"));
	}

	public void createBlock(Program program) throws LockException, MemoryConflictException,
			AddressOverflowException, DuplicateNameException {
		if (blockName == null || addressString == null || length <= 0) {
			return;
		}

		Memory mem = program.getMemory();
		Address addr = XmlProgramUtilities.parseAddress(program.getAddressFactory(), addressString);

		MemoryBlock block;
		if (bitMappedAddress != null) {
			Address mappedAddr =
				XmlProgramUtilities.parseAddress(program.getAddressFactory(), bitMappedAddress);
			block = mem.createBitMappedBlock(blockName, addr, mappedAddr, length, false);
		}
		else if (initialized) {
			try {
				block =
					mem.createInitializedBlock(blockName, addr, length, (byte) 0,
						TaskMonitor.DUMMY, false);
			}
			catch (CancelledException e) {
				throw new AssertException(e); // unexpected
			}
		}
		else {
			block = mem.createUninitializedBlock(blockName, addr, length, false);
		}
		block.setRead(readPermission);
		block.setWrite(writePermission);
		block.setExecute(executePermission);
		block.setVolatile(volatilePermission);
	}

}
