/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public class GenerateMaskedBitStringScript extends GhidraScript {

	public void run() throws Exception {
		Memory mem = currentProgram.getMemory();

		//Gets the start and end address to search through
		Address endAddress = currentProgram.getMaxAddress();

		Address currentPosition = currentProgram.getMinAddress();
		byte[] values =
			askBytes("Enter byte values",
				"Please enter the list of byte values you want to search for");
		byte[] masks =
			askBytes("Enter byte masks", "Please enter the list of byte masks you want to use");

		createMaskedBitString(values, masks);

		int count = 0;
		while (currentPosition.compareTo(endAddress) < 0) {
			if (monitor.isCancelled())
				return;

			//Searches memory for the given mask and value.
			currentPosition =
				mem.findBytes(currentPosition, endAddress, values, masks, true, monitor);

			//Determines if a new location was found.
			if (currentPosition == null) {
				break;
			}

			//	println(currentPosition.toString());
			count++;

			currentPosition = currentPosition.add(1);
		}
		println("\nTotal count: " + count);
	}

	private String createMaskedBitString(byte values[], byte masks[]) {

		String bitString = new String();

		//check that value and mask lengths are equal
		if (values.length != masks.length) {
			println("values and masks are different lengths");
			return null;
		}

		//pull the bits out of each byte and create search string
		for (int i = 0; i < values.length; i++) {
			for (int j = 0; j < 8; j++) {
				if (((masks[i] >> (7 - j)) & 1) == 0) {
					bitString = bitString.concat(".");
				}
				else if (((values[i] >> (7 - j)) & 1) == 0) {
					bitString = bitString.concat("0");
				}
				else {
					bitString = bitString.concat("1");
				}
			}
			bitString = bitString.concat(" ");
		}
		println(bitString);
		return bitString;
	}
}
