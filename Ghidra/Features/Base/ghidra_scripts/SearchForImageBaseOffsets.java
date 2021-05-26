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
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;

public class SearchForImageBaseOffsets extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("No open program");
			return;
		}

		if (currentProgram.getMemory().isBigEndian()) {
			println("This script only looks for little endian image base offsets");
			return;
		}

		Address imageBase = currentProgram.getImageBase();

		long currentAddressOffset = currentAddress.getOffset();
		long imageBaseOffset = imageBase.getOffset();

		long currentAddressIbo = imageBaseOffset ^ currentAddressOffset;

		byte searchBytes[] = createLittleEndianByteArray(currentAddressIbo, 8);
		println("searching for possible ibo64 references to " + currentAddress.toString() + " ...");
		searchForByteArray(searchBytes);

		searchBytes = createLittleEndianByteArray(currentAddressIbo, 4);
		println("searching for possible ibo32 references to " + currentAddress.toString() + " ...");
		searchForByteArray(searchBytes);

	}

	/**
	 * Method to create a byte array out of the given long value
	 * @param value the given value
	 * @param numBytes the number of bytes from the low end of the value to copy into the array
	 * @return the little endian byte array for the given value
	 * @throws CancelledException if cancelled
	 */
	private byte[] createLittleEndianByteArray(long value, int numBytes)
			throws CancelledException {


		byte byteArray[] = new byte[numBytes];

		for (int i = 0; i < numBytes; i++) {
			monitor.checkCanceled();
			byteArray[i] = (byte) (value >> (8 * i) & 0xff);
		}

		return byteArray;
	}

	private void searchForByteArray(byte[] byteArray) throws CancelledException {
		Address start = currentProgram.getMinAddress();
		Address found = find(start, byteArray);
		while (found != null) {
			monitor.checkCanceled();
			println(found.toString());
			start = found.add(1);
			found = find(start, byteArray);
		}
	}

}
