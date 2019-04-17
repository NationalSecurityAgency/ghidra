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
//finds and creates strings that end with  '\n'
//@category Memory

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class CreateStringScript extends GhidraScript {
	private byte TERMINATOR = '\n';

	@Override
	public void run() throws Exception {

		Address addr = find(null, TERMINATOR);
		while (addr != null) {
			createString(addr);
			try {
				addr = addr.addNoWrap(1);
				addr = find(addr, TERMINATOR);
			}
			catch (AddressOverflowException e) {
				// must be at largest possible address - so we are done
			}
		}
	}

	private void createString(Address endAddr) {
		Address startAddr = findStartOfString(endAddr);
		int length = (int) endAddr.subtract(startAddr) + 1;
		if (length < 4) {
			println("Too small, Skipping " + startAddr);
			return;
		}
		try {
			myCreateAsciiString(startAddr, length);
			createLabelForString(startAddr, length);
		}
		catch (Exception e) {
			println("error creating string at " + startAddr + ". Reason: " + e.getMessage());
		}
	}

	private void myCreateAsciiString(Address startAddr, int length) throws Exception {
		currentProgram.getListing().createData(startAddr, new StringDataType(), length);
	}

	private Address findStartOfString(Address endAddr) {
		Address addr = endAddr;
		Address startAddr = endAddr;
		try {
			addr = addr.subtract(1);
			while (isAsciiAndNotTerminator(addr)) {
				startAddr = addr;
				addr = addr.subtractNoWrap(1);
			}
		}
		catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return startAddr;
	}

	private boolean isAsciiAndNotTerminator(Address addr) {
		try {
			byte b = currentProgram.getMemory().getByte(addr);
			if (b == TERMINATOR) {
				return false;
			}
			return (b >= 0x20 && b <= 0x7f) || b == '\n' || b == '\r' || b == '\t';
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	private boolean createLabelForString(Address addr, int length) throws Exception {
		Listing listing = currentProgram.getListing();
		Memory memory = currentProgram.getMemory();
		Data data = listing.getDataAt(addr);
		String value = (String) data.getValue();
		if (value == null) {
			return false;
		}

		boolean needsUnderscore = true;
		StringBuffer buf = new StringBuffer();
		buf.append("s");
		byte[] bytes = new byte[length];
		try {
			memory.getBytes(addr, bytes);
		}
		catch (MemoryAccessException e) {
		}
		for (int i = 0; i < length; i++) {
			char c = (char) bytes[i];
			if (c > 0x20 && c <= 0x7f) {
				if (needsUnderscore) {
					buf.append('_');
					needsUnderscore = false;
				}
				buf.append(c);
			}
			else if (c != 0) {
				needsUnderscore = true;
			}
		}
		String newLabel = buf.toString();

		createLabel(addr, newLabel, true);
		return true;
	}
}
