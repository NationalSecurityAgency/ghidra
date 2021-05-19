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
// This script searches for image base offset references of size 32 and 64 to the current cursor
// location. This script only works on programs of size 32 and 64. The results are both printed to
// the console and are presented in a table with two tabs, one for each size. To apply data types to
// undefined ones that are found simply select the desired ones from the table then drag either the
// ImageBaseOffset32 or ImageBaseOffset64 data type, whichever is applicable, onto the selection in 
// the listing from the Data Type Manager.
// 
//@category Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;

public class SearchForImageBaseOffsetsScript extends GhidraScript {

	static final int POINTER_BYTE_LEN_64BIT = 8;
	static final int POINTER_BYTE_LEN_32BIT = 4;
	static final byte BYTE_MASK = (byte) 0xff;
	static final int BITS_PER_BYTE = 8;

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			println("No open program");
			return;
		}

		long defaultPointerSize = currentProgram.getDefaultPointerSize();
		if (defaultPointerSize != 4 && defaultPointerSize != 8) {
			println("This script only works on 32 or 64 bit programs");
			return;
		}

		Address imageBase = currentProgram.getImageBase();

		boolean isBigEndian = currentProgram.getMemory().isBigEndian();

		long currentAddressOffset = currentAddress.getOffset();
		long imageBaseOffset = imageBase.getOffset();

		long currentAddressIbo = currentAddressOffset - imageBaseOffset;

		byte searchBytes[] =
			createSearchArray(currentAddressIbo, POINTER_BYTE_LEN_64BIT, isBigEndian);
		println("searching for possible ibo64 references to " + currentAddress.toString() + " ...");
		AddressSet ibo64refs = searchForByteArray(searchBytes);
		printAddresses(ibo64refs);

		searchBytes = createSearchArray(currentAddressIbo, POINTER_BYTE_LEN_32BIT, isBigEndian);
		println("searching for possible ibo32 references to " + currentAddress.toString() + " ...");
		AddressSet ibo32refs = searchForByteArray(searchBytes);
		printAddresses(ibo32refs);

		show("64-bit ImageBaseOffset References", ibo64refs);
		show("32-bit ImageBaseOffset References", ibo32refs);

	}

	/**
	 * Method to return an appropriate sized and endian-ordered byte array out of the given long value
	 * @param value the given value
	 * @param numBytes the number of bytes to copy into the array
	 * @return the appropriate sized and endian-ordered byte array for the given value
	 * @throws CancelledException if cancelled
	 */
	private byte[] createSearchArray(long value, int numBytes, boolean isBigEndian)
			throws CancelledException {

		if (isBigEndian) {
			return createBigEndianByteArray(value, numBytes);
		}
		return createLittleEndianByteArray(value, numBytes);
	}

	/**
	 * Method to create a little endian ordered byte array out of the given long value
	 * @param value the given value
	 * @param numBytes the number of bytes to copy into the array
	 * @return the little endian byte array for the given value
	 * @throws CancelledException if cancelled
	 */
	private byte[] createLittleEndianByteArray(long value, int numBytes)
			throws CancelledException {


		byte byteArray[] = new byte[numBytes];

		for (int i = 0; i < numBytes; i++) {
			monitor.checkCanceled();
			byteArray[i] = (byte) (value >> (BITS_PER_BYTE * i) & BYTE_MASK);
		}

		return byteArray;
	}

	/**
	 * Method to create a big endian byte array out of the given long value
	 * @param value the given value
	 * @param numBytes the number of bytes to copy into the array
	 * @return the big endian byte array for the given value
	 * @throws CancelledException if cancelled
	 */
	private byte[] createBigEndianByteArray(long value, int numBytes) throws CancelledException {

		byte byteArray[] = new byte[numBytes];

		for (int i = 0; i < numBytes; i++) {
			monitor.checkCanceled();
			byteArray[i] = (byte) (value >> (8 * (numBytes - (i + 1))) & 0xff);
		}

		return byteArray;
	}

	/**
	 * Method to search for the given byte array and print the address(es) where it is found
	 * @param byteArray the given byte array
	 * @throws CancelledException if cancelled
	 */
	private AddressSet searchForByteArray(byte[] byteArray) throws CancelledException {

		AddressSet addressSet = new AddressSet();

		Address start = currentProgram.getMinAddress();
		Address found = find(start, byteArray);
		while (found != null) {
			monitor.checkCanceled();
			addressSet.add(found);
			start = found.add(1);
			found = find(start, byteArray);
		}

		return addressSet;
	}

	private void printAddresses(AddressSet addressSet) throws CancelledException {

		AddressIterator addresses = addressSet.getAddresses(true);
		while (addresses.hasNext()) {
			monitor.checkCanceled();
			Address address = addresses.next();
			println(address.toString());
		}
	}

}
