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
//Useful for getting bytes into a program that have been copied and pasted
//as text onto a website or other text documents. If there is no program open
//when the script is run, you will be prompted to select a processor and a
//new empty program will be created. Text in the copy buffer will be parsed
//to extract address and bytes, and everything else will be ignored.
//Example listing text:
//	LAB_0007aaca	XREF[1]:
//	0007aac0(j)
//			0007aaca 01 24
//				movs		r4,#0x1
//			0007aacc 00 28
//				cmp			r0,#0x0
//			0007aad2 00 24
//				movs		r4,#0x0
//
//			0007aad6 1f d0
//				beq			LAB_0007ab18
//@category Program
//@menupath Edit.Paste Listing Text
import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.*;

import docking.dnd.GClipboard;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.util.exception.CancelledException;

public class PasteCopiedListingBytesScript extends GhidraScript {
	public void run() throws Exception {
		int id = 0;
		if (currentProgram == null) {
			runScript("CreateEmptyProgramScript");
			currentProgram = state.getTool().getService(ProgramManager.class).getCurrentProgram();
		}
		if (currentProgram == null) {
			print("No Program");
			return;
		}
		Memory memory = currentProgram.getMemory();

		// get data from the clip board and turn it into a string
		String ClipboardText = retrieveClipBoardText();
		if (ClipboardText == null) {
			println("Nothing is copied to your clip board");
			return;
		}

		// evaluate the copy buffer and get the byte array
		Map<Address, byte[]> bytesToAdd = parseListingStringToByte(ClipboardText);
		if (bytesToAdd.isEmpty()) {
			println("There are no bytes copied to your clip board");
			return;
		}

		// Check if memory block with the byte+address exists
		boolean exists = checkForExistingMemory(memory, bytesToAdd);

		// quit if any bytes/addresses exist
		if (exists) {
			boolean overwrite =
				askYesNo("Bytes Exist", "Do you wish to overwrite existing memory?");
			if (!overwrite) {
				println("stopped");
				return;
			}
		}

		id = currentProgram.startTransaction("Create Missing Memory");
		try {
			// create memoryBlocks for address ranges that don't already exist
			createMissingMemory(bytesToAdd, memory);

			// set bytes in memory blocks
			setBytesInMemory(bytesToAdd, memory);
		}
		finally {
			currentProgram.endTransaction(id, true);
		}
		println("Created " + getNeededAddressSet(bytesToAdd));
	}

	private void createMissingMemory(Map<Address, byte[]> bytesToAdd, Memory memory)
			throws CancelledException, Exception {
		AddressSet neededMem = getNeededAddressSet(bytesToAdd);
		AddressSet Overlap = memory.intersect(neededMem);
		neededMem = neededMem.subtract(Overlap);
		for (AddressRange addr : neededMem) {
			memory.createInitializedBlock("PastedBytes", addr.getMinAddress(), addr.getLength(),
				(byte) 0, monitor, false);
		}
	}

	private String retrieveClipBoardText() throws UnsupportedFlavorException, IOException {
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable contents = systemClipboard.getContents(this);
		if (contents.toString().isEmpty()) {
			return null;
		}
		if (contents.isDataFlavorSupported(DataFlavor.stringFlavor)) {
			return (String) contents.getTransferData(DataFlavor.stringFlavor);
		}
		return null;
	}

	private void setBytesInMemory(Map<Address, byte[]> byteMap, Memory memory)
			throws CancelledException, Exception, MemoryAccessException, MemoryBlockException {
		for (Address addr : byteMap.keySet()) {
			monitor.checkCancelled();
			setBytes(addr, byteMap.get(addr));
		}
	}

	private boolean checkForExistingMemory(Memory memory, Map<Address, byte[]> Addresses)
			throws Exception {
		AddressSet neededMem = getNeededAddressSet(Addresses);
		AddressSet Overlap = memory.intersect(neededMem);
		if (Overlap.isEmpty()) {
			return false;
		}
		return true;
	}

	private AddressSet getNeededAddressSet(Map<Address, byte[]> Addresses)
			throws CancelledException {
		AddressSet addrSet = new AddressSet();
		for (Address addr : Addresses.keySet()) {
			monitor.checkCancelled();
			int addrCount = Addresses.get(addr).length;
			addrSet.add(addr, addr.add(addrCount - 1));
		}
		return addrSet;
	}

	private Map<Address, byte[]> parseListingStringToByte(String ClipboardText)
			throws CancelledException {
		String[] bufferLines = ClipboardText.split("\n");
		Map<Address, byte[]> newMap = new HashMap<Address, byte[]>();
		for (String line : bufferLines) {
			monitor.checkCancelled();
			line = line.trim();
			String[] words = line.split(" ");
			String startOfLine = words[0];
			Address firstAddress = toAddr(startOfLine);
			if (firstAddress == null) {
				continue;
			}
			List<String> bytesFound = new ArrayList<String>();
			for (String word : words) {
				monitor.checkCancelled();
				if (word == words[0]) {
					continue;
				}
				if (word.isBlank() || word.length() > 2) {
					break;
				}
				try {
					Integer.parseInt(word, 16);
				}
				catch (Exception e) {
					break;
				}
				bytesFound.add(word);

			}
			byte[] newBytes = new byte[bytesFound.size()];
			int i = 0;
			for (String byteString : bytesFound) {
				monitor.checkCancelled();
				byte bVal = (byte) Integer.parseInt(byteString, 16);
				newBytes[i++] = bVal;
			}
			newMap.put(firstAddress, newBytes);
		}
		return newMap;
	}
}
