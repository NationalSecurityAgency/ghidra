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
// Useful for getting bytes into a program that have been copied and pasted
// as text onto a website or other text documents. The bytes can be from a listing
// or from a hexdump.
//
// If there is no program open when the script is run, you will be prompted
// to select a processor and a new empty program will be created.
//
// Text in the clipboard will be parsed
// to extract address and bytes, and everything else will be ignored.
//
// Example listing text:
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
//
// Example hexdump text:
//  Hex dump of section '.text':
// NOTE: This section has relocations against it, but these have NOT been applied to this dump.
//  0x00000000 80b487b0 00aff860 c7e90023 3b683b61 .......`...#;h;a
//  0x00000010 b7f92030 7b61fb68 1a4607f1 100393e8 .. 0{a.h.F......
//  ...
//  0x00000210 1a443b6a 13441846 1437bd46 5df8047b .D;j.D.F.7.F]..{
//
//@category Program
//@menupath Edit.Paste Listing Text
import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import docking.dnd.GClipboard;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.CancelledException;

public class PasteCopiedListingBytesScript extends GhidraScript {
	
	@Override
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
		String clipBoardText = retrieveClipBoardText();
		if (clipBoardText == null) {
			println("Nothing is copied to your clip board");
			return;
		}

		// evaluate the copy buffer and get the byte array
		Map<Address, byte[]> bytesToAdd = parseListingStringToByte(clipBoardText);
		if (bytesToAdd.isEmpty()) {
			println("There are no bytes copied to your clip board");
			return;
		}
		
		coalesceBytes(bytesToAdd);

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

	private void coalesceBytes(Map<Address, byte[]> bytesToAdd) {
		// Map is assumed to be a sorted Map
		Set<Entry<Address, byte[]>> entrySet = bytesToAdd.entrySet();
		Iterator<Entry<Address, byte[]>> iterator = entrySet.iterator();
		Map.Entry<Address, byte[]> entryA = iterator.next();
		while (entryA != null && iterator.hasNext()) {
			Map.Entry<Address, byte[]> entryB = iterator.next();
			Address addrA = entryA.getKey();
			Address addrB = entryB.getKey();
			byte bytesA[] = entryA.getValue();
			if (addrA.add(bytesA.length).equals(addrB)) {
				byte bytesB[] = entryB.getValue();
				// coalesce, and res-start iterator
				byte concatBytes[] = Arrays.copyOf(bytesA,bytesA.length+bytesB.length);
				System.arraycopy(bytesB, 0, concatBytes, bytesA.length, bytesB.length);
			
				bytesToAdd.replace(addrA, concatBytes);
				bytesToAdd.remove(addrB);
				iterator = entrySet.iterator();
				entryA = null;
				if (iterator.hasNext()) {
					entryA = iterator.next();
				}
				continue;
			}
			entryA = entryB;
		}
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
		// TreeMap so the entries will be sorted by Address
		Map<Address, byte[]> newMap = new TreeMap<Address, byte[]>();
		String[] bufferLines = ClipboardText.split("\n");
		
		Address firstAddress = null;
		
		// For each line, look for address and bytes, accumlate address/byteStrings
		// in a list, throwing out any text that can't be parsed
		for (String line : bufferLines) {
			monitor.checkCancelled();
			line = line.trim();
			if (line.isEmpty()) {
				continue;
			}
			String[] words = line.split(" ");
			if (words.length == 0) {
				continue;
			}
			String startOfLine = words[0];
			// if start of line word is > 2 assume address
			//  other wise, consider it a continuation of the
			//  previous address
			//     001325a4 03 00        0b0           sethi      %hi(0x1000),g1
            //              00 04

			boolean skipFirstWord = false;
			if (startOfLine.length() > 2) {
				firstAddress = toAddr(startOfLine);
				skipFirstWord = true;
			}
			if (firstAddress == null) {
				continue;
			}
			List<String> bytesStringsList = new ArrayList<String>();
			int numBytesFound = 0;
			for (String word : words) {
				monitor.checkCancelled();
				if (skipFirstWord) {
					skipFirstWord = false;
					continue;
				}
				// break if bytes already found and separator more than one " "
				//       001325a4 03 00        0b0           sethi      %hi(0x1000),g1
				if (numBytesFound > 0 && word.isBlank()) {
					break;
				}
				int len = word.length();
				if (word.isBlank() || len > 8 || (len % 2) != 0) {
					break;
				}
				try {
					Long.parseLong(word, 16);
				}
				catch (Exception e) {
					break;
				}
				bytesStringsList.add(word);
				numBytesFound += len / 2;
			}
			
			// parse found address/byteStrings into byte array
			byte newBytes[] = parseHexStrings(bytesStringsList,numBytesFound);
			newMap.put(firstAddress, newBytes);
			firstAddress = firstAddress.add(newBytes.length);
		}
		return newMap;
	}

	private byte[] parseHexStrings(List<String> byteStringsList, int numBytesFound)
			throws CancelledException {
		byte[] newBytes = new byte[numBytesFound];
		int byteArrayIndex = 0;
		for (String byteString : byteStringsList) {
			monitor.checkCancelled();
			int numBytes = byteString.length() / 2;
			byte[] bytes = NumericUtilities.convertStringToBytes(byteString);
			System.arraycopy(bytes, 0, newBytes, byteArrayIndex, bytes.length);
			byteArrayIndex += bytes.length;
		}
		return newBytes;
	}
}
