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
package ghidra.program.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

/**
 * The <CODE>BytesFieldLocation</CODE> class provides specific information
 *  about the BYTES field within a program location.
*/

public class BytesFieldLocation extends CodeUnitLocation {

	/**
	 * Create a new BytesFieldLocation which represents a specific byte address.
	 * @param program the program for this location.
	 * @param addr the address of the code unit containing this location.
	 * @param byteAddress the address of this location which can be the address of a specific
	 * byte within a code unit.
	 * @param componentPath the data component path which is specified as an array of indexes
	 * where each index indicates the index into nested structures. For instructions or
	 * simple data, this should be null.
	 * @param columnInByte the character position in the the bytes
	 */
	public BytesFieldLocation(Program program, Address addr, Address byteAddress,
			int[] componentPath, int columnInByte) {
		super(program, addr, byteAddress, componentPath, 0, 0, columnInByte);
	}

	/**
	 * Creates a new BytesFieldLocation for the given address.
	 * The address will be adjusted to the beginning of the code unit containing
	 * that address(if it exists).  The original address can be retrieved using
	 * the "getByteAddress()" method.
	 * @param program the program that this location is related.
	 * @param addr the address of the byte for this location.
	 */
	public BytesFieldLocation(Program program, Address addr) {
		super(program, addr, getComponentPath(program, addr), 0, 0, 0);
	}

	private static int[] getComponentPath(Program program, Address addr) {
		CodeUnit cu = program.getListing().getCodeUnitContaining(addr);

		// if the codeunit is a data, try and dig down to the lowest subdata containing the address
		if (cu instanceof Data) {
			Data data = (Data) cu;
			Data subData = data.getPrimitiveAt((int) addr.subtract(data.getAddress()));
			return subData != null ? subData.getComponentPath() : data.getComponentPath();
		}
		return null;
	}

	/**
	 * Default constructor needed for restoring
	 * a byte field location from XML.
	 */
	public BytesFieldLocation() {
	}

	/**
	 * Returns the index of byte that represents the current program location.
	 * Sources that do not get this specific should simply return 0.
	 */
	public int getByteIndex() {
		return (int) getByteAddress().subtract(getAddress());
	}

	/**
	 * This is overridden here because previous versions used to store the byte index in the
	 * column field.  So if anyone was incorrectly using getColumn() to get the byte index,
	 * then this override will allow that to keep working.
	 */
	@Override
	public int getColumn() {
		return getByteIndex();
	}

	/**
	 * Returns the character position within the byte specified by getByteIndex().  Normally,
	 * this is 1,2, or 3 corresponding to before the byte, between the nibbles of the byte or
	 * past the byte.  Sometimes, extra delimiters may exist allowing the position to be
	 * greater than 3.
	 */
	public int getColumnInByte() {
		return getCharOffset();
	}

	public Address getAddressForByte() {
		return getAddress().add(getByteIndex());
	}

}
