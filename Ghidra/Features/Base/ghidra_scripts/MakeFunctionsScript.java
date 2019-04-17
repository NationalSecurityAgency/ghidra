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
// Script to ask user for a byte sequence that is a common function start
// make functions at those locations
// if code has only one block it asks the user where the data block is and splits the program into 
// code and data blocks
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class MakeFunctionsScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		Memory memory = currentProgram.getMemory();
		byte[] functionBytes =
			askBytes("Enter Byte Pattern",
				"Please enter your function byte pattern separated by spaces");

		while ((!monitor.isCancelled()) && ((functionBytes == null) || (functionBytes.length == 0))) {
			functionBytes =
				askBytes("Invalid Byte Pattern",
					"Please re-enter your function byte pattern in separated by spaces");
		}
		String textBytes = "";
		for (int i = 0; i < functionBytes.length; i++) {
			textBytes = textBytes.concat(toHexString(functionBytes[i], true, false));
			textBytes = textBytes.concat(" ");
		}
		println("Searching for " + textBytes + ". . .");

		MemoryBlock[] memoryBlock = currentProgram.getMemory().getBlocks();
		if (memoryBlock.length == 1) {
			Address dataAddress =
				askAddress("Create data block",
					"Please enter the start address of the data section.");
			memory.split(memoryBlock[0], dataAddress);
			// get the blocks again to get new split one
			memoryBlock = currentProgram.getMemory().getBlocks();
			if (memoryBlock[1].contains(dataAddress)) {
				memoryBlock[1].setName("Data");
				memoryBlock[1].setExecute(false);
			}
			else {
				if (memoryBlock[0].contains(dataAddress)) {
					memoryBlock[0].setName("Data");
					memoryBlock[0].setExecute(false);
				}
			}
		}
		int foundCount = 0;
		int madeCount = 0;
		for (int i = 0; i < memoryBlock.length; i++) {
			if (memoryBlock[i].isExecute()) {
				boolean keepSearching = true;
				Address start = memoryBlock[i].getStart();
				Address end = memoryBlock[i].getEnd();

				while ((keepSearching) && (!monitor.isCancelled())) {
					Address found =
						memory.findBytes(start, end, functionBytes, null, true, monitor);
					if ((found != null) && memoryBlock[i].contains(found)) {
						foundCount++;
						Function testFunc = getFunctionContaining(found);
						if (testFunc == null) {
							boolean didDisassemble = disassemble(found);
							if (didDisassemble) {
								Function func = createFunction(found, null);
								if (func != null) {
									println("Made function at address: " + found.toString());
									madeCount++;
								}
								else {
									println("***Function could not be made at address: " +
										found.toString());
								}
							}
						}
						else {
							println("Function already exists at address: " + found.toString());
						}
						start = found.add(4);
					}
					else {
						keepSearching = false;
					}
				}

			}

		}
		if (foundCount == 0) {
			println("No functions found with given byte pattern.");
			return;
		}
		if (madeCount == 0) {
			println("No new functions made with given byte pattern.");
		}

	}

}
