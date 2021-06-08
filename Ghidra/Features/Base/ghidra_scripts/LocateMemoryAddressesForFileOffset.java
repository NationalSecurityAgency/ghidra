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

//This example script locates a memory address for a file offset.  
//Prompt user for a file offset.
//Print the associated memory address to the Ghidra console
//Print the file offset as a Ghidra comment at the memory address in the Ghidra Listing
//If multiple addresses are located, then print the addresses to the console (do not set a 
//Ghidra comment)
//@category Examples

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;

public class LocateMemoryAddressesForFileOffset extends GhidraScript {

	@Override
	public void run() throws Exception {
		long myFileOffset = getFileOffset();
		Memory mem = currentProgram.getMemory();
		List<Address> addressList = mem.locateAddressesForFileOffset(myFileOffset);
		if (addressList.isEmpty()) {
			println("No memory address found for: " + Long.toHexString(myFileOffset));
		}
		else if (addressList.size() == 1) {
			Address address = addressList.get(0);
			processAddress(address, mem.getBlock(address).getName(), myFileOffset);

		}
		//address set size is > 1, file offset matches to multiple addresses.  
		//Let the user decide which address they want.
		else {
			println("Possible memory block:address are:");
			for (Address addr : addressList) {
				println(mem.getBlock(addr).getName() + ":" + addr.toString());
			}
		}
	}

	public long getFileOffset()
			throws CancelledException, NumberFormatException, IllegalArgumentException {
		String userFileOffset =
			askString("File offset", "Please provide a hexadecimal file offset");
		long myFileOffset = 0;
		myFileOffset = Long.parseLong(userFileOffset, 16);
		if (myFileOffset < 0) {
			throw new IllegalArgumentException(
				"Offset cannot be a negative value." + userFileOffset);
		}
		return myFileOffset;
	}

	public void processAddress(Address addr, String memBlockName, long fileOffset) {
		println("File offset " + Long.toHexString(fileOffset) +
			" is associated with memory block:address " + memBlockName + ":" + addr.toString());
		CodeUnit myCodeUnit = currentProgram.getListing().getCodeUnitContaining(addr);
		String comment = myCodeUnit.getComment(0);
		if (comment == null) {
			myCodeUnit.setComment(0,
				this.getScriptName() + ": File offset: " + Long.toHexString(fileOffset) +
					", Memory block:address " + memBlockName + ":" + addr.toString());
		}
		else {
			myCodeUnit.setComment(0,
				comment + ", " + this.getScriptName() + ": File offset: " +
					Long.toHexString(fileOffset) + ", Memory block:address " + memBlockName + ":" +
					addr.toString());
		}
	}
}
