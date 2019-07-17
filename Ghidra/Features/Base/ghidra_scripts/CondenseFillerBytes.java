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
//This script collapses filler bytes in between functions.
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.AlignmentDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramUtilities;

import java.util.*;

public class CondenseFillerBytes extends GhidraScript {

	Listing listing;
	Memory memory;

	@Override
	public void run() throws Exception {
		listing = currentProgram.getListing();
		memory = currentProgram.getMemory();
		String filler = null;

		AddressSet possibleAddrSet = new AddressSet();

		// Ask for min run length
		int minBytes =
			askInt("CondenseFillerBytes", "Enter minimum number of sequential bytes to collapse");
		byte[] prgmFillerBytes = new byte[minBytes];  // filler bytes found in program

		// Ask for a fill value.  "Auto" wants the program to try and figure out the value.
		String fillValue =
			askString(
				"CondenseFillerBytes - Enter Fill Value",
				"Enter fill byte to search for and collapse (Examples:  0, 00, 90, cc).  "
					+ "\"Auto\" will make the program determine the value (by greatest count).  0x",
				"Auto");

		// Check response
		if (fillValue.equalsIgnoreCase("auto")) {
			filler = "0x" + determineFillerValue();
		}
		else {
			filler = "0x" + new String(fillValue);
		}
		println("filler byte chosen: " + filler);

		// Create array of minBytes length initialized to fillerByte    	    	    	
		byte[] targetFillerBytes = new byte[minBytes];
		byte fillerByte = Integer.decode(filler).byteValue();
		Arrays.fill(targetFillerBytes, fillerByte);

		// Iterate through functions
		FunctionIterator funcIter = listing.getFunctions(true);
		while (funcIter.hasNext() && !monitor.isCancelled()) {

			// Get undefined byte immediately following function
			Address fillerAddr = funcIter.next().getBody().getMaxAddress().next();
			Data undefinedData = listing.getUndefinedDataAt(fillerAddr);
			if (undefinedData == null) {
				// No undefined filler bytes found, keep going to next function
				continue;
			}

			// Check has min run length		
			memory.getBytes(fillerAddr, prgmFillerBytes);
			if (Arrays.equals(prgmFillerBytes, targetFillerBytes)) {

				// Determine actual length of filler bytes
				int fillerLen = 1;
				String undefDataStringRep = undefinedData.getDefaultValueRepresentation();
				AddressSet set =
					new AddressSet(currentProgram, fillerAddr, currentProgram.getMaxAddress());
				AddressIterator addrIter = set.getAddresses(fillerAddr.next(), true);
				while (addrIter.hasNext()) {
					Address nextAddr = addrIter.next();
					if (listing.getUndefinedDataAt(nextAddr) == null ||
						!listing.getUndefinedDataAt(nextAddr).getDefaultValueRepresentation().equalsIgnoreCase(
							undefDataStringRep)) {
						break;
					}
					++fillerLen;
				}

				// Check if immediate data after filler bytes is undefined				
				if (listing.isUndefined(fillerAddr.add(fillerLen), fillerAddr.add(fillerLen))) {
					// Not in between defined data/instructions, add to list										
					possibleAddrSet.add(fillerAddr);

					println("*** Possible Alignment datatype at " + fillerAddr.toString());
					continue;
				}

				// Replace filler bytes with Alignment type
				listing.createData(fillerAddr, new AlignmentDataType(), fillerLen);

				println("Applied Alignment datatype at " + fillerAddr.toString());
			}
		}

		// Check if any potential filler bytes were found and display to user in table
		if (!possibleAddrSet.isEmpty()) {
			popup("Script complete.\n\n"
				+ "Some additional possible filler bytes where the Alignment datatype could be applied were found.\n"
				+ "Press OK to see a table of these addresses.");

			show("Possible Addresses", possibleAddrSet);
		}
	}

	/**
	 * This function tries to determine the fill value used by the current program.
	 * The byte value occurring most is the winner.
	 * 
	 * @return filler
	 * @throws Exception
	 */
	private String determineFillerValue() throws Exception {

		FunctionIterator funcIter = listing.getFunctions(true);
		HashMap<String, Integer> fillValuesHash = new HashMap<String, Integer>();

		while (funcIter.hasNext() && !monitor.isCancelled()) {

			// Get undefined byte immediately following function
			Address maxAddress = funcIter.next().getBody().getMaxAddress();
			Data undefinedData = listing.getUndefinedDataAt(maxAddress.next());
			if (undefinedData == null) {
				// No undefined filler bytes found, keep going to next function
				continue;
			}

			// Add filler to hash
			String key = ProgramUtilities.getByteCodeString(undefinedData);
			if (fillValuesHash.containsKey(key)) {
				// Hash already contains key, just increment count
				int val = fillValuesHash.get(key);
				fillValuesHash.put(key, val + 1);
			}
			else {
				// Add to hash
				fillValuesHash.put(key, 1);
			}
		}

		println("Possible filler values (and their counts): " + fillValuesHash.toString());

		// Decide that filler value is the one with the greatest count				
		String filler = getValueWithHighestCount(fillValuesHash);

		return filler;
	}

	private String getValueWithHighestCount(HashMap<String, Integer> fillValuesHash) {

		// Determine val with highest count
		Iterator<Integer> valIterator = fillValuesHash.values().iterator();
		int max = valIterator.next();
		while (valIterator.hasNext()) {
			int nextVal = valIterator.next();
			if (nextVal > max) {
				max = nextVal;
			}
		}

		// Determine key corresponding to max val
		Iterator<String> keyIterator = fillValuesHash.keySet().iterator();
		while (keyIterator.hasNext()) {
			String nextKey = keyIterator.next();
			if (fillValuesHash.get(nextKey).compareTo(max) == 0) {
				return nextKey;
			}
		}

		// Should theoretically never reach here
		return null;
	}

}
