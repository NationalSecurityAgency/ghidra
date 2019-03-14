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
package ghidra.program.model.lang;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * The Mask class is used to perform some basic bit tests on an
 * array of bits.
 */

public interface Mask {

	/**
	*   Test if the given object is equal to this object. Two masks are
	*   equal if they have exactly the same values in thier byte arrays.
	*   @param obj the object to be tested for equals
	*   @return true if the object is equal to this mask, false otherwise.
	*/

	boolean equals(Object obj);

	/**
	 * Check if the mask represented by the byte array is equal to this one.
	 * @param mask mask represented as byte array
	 * @return true if the masks are the same, false otherwise
	 */
	boolean equals(byte[] mask);

	/**
	 * Apply the mask to a byte array.
	 *   @param cde the array that contains the values to be masked
	 *   @param results the array to contain the results.
	 *   @return the resulting byte array.
	* @exception IncompatibleMaskException thrown if byte
	* arrays are not of the correct size
	 */
	byte[] applyMask(byte[] cde, byte[] results) throws IncompatibleMaskException;

	/**
	 * Apply the mask to a byte array.
	 *   @param cde the array that contains the values to be masked
	 *   @param cdeOffset the offset into the array that contains the values to be masked
	 *   @param results the array to contain the results.
	 *   @param resultsOffset the offset into the array that contains the results
	* @exception IncompatibleMaskException thrown if byte
	* arrays are not of the correct size
	 */
	void applyMask(byte[] cde, int cdeOffset, byte[] results, int resultsOffset)
			throws IncompatibleMaskException;

	/**
	* Apply the mask to a memory buffer.
	*   @param buffer the memory buffer that contains the values to be masked
	*   @return the resulting masked byte array.
	* @exception MemoryAccessException thrown if mask exceeds the available data 
	* within buffer
	 */
	byte[] applyMask(MemBuffer buffer) throws MemoryAccessException;

	/**
	*   Tests if the results of apply the mask to the given array matches a
	*   target array.
	*   @param cde the source bytes.
	*   @param target the result bytes to be tested.
	*   @return true if the target array is equal to the source array with
	*   the mask applied.
	* @exception IncompatibleMaskException thrown if byte
	* arrays are not of the correct size
	*/
	boolean equalMaskedValue(byte[] cde, byte[] target) throws IncompatibleMaskException;

	/**
	*   applies the complement of the mask to the given byte array.
	*   @param msk the bytes to apply the inverted mask.
	*   @param results the array for storing the results.
	*   @return the results array.
	* @exception IncompatibleMaskException thrown if byte
	* arrays are not of the correct size
	*/
	byte[] complementMask(byte[] msk, byte[] results) throws IncompatibleMaskException;

	/**
	*   Tests if the given mask matches the this mask for the first n
	*   bytes, where n is the size of the given mask.
	*   @param msk the bytes to be tested to see if they match the first
	*   bytes of this mask.
	*   @return true if the bytes match up to the length of the passed in
	*   byte array.
	* @exception IncompatibleMaskException thrown if byte
	* arrays are not of the correct size
	*/
	boolean subMask(byte[] msk) throws IncompatibleMaskException;

	/** 
	 * Returns the bytes that make up this mask.
	 */
	byte[] getBytes();
}
