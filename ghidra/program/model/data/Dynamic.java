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
package ghidra.program.model.data;

import ghidra.program.model.mem.MemBuffer;

/**
 * A DataType class that must compute its length based upon actual data.
 * This type may be referred to directly within a listing (including pointers).
 * This type may only appear within a structure if canSpecifyLength() returns 
 * true.  A pointer to this type can always appear within a structure.
 * TypeDef to this data-type should not be allowed.
 */
public interface Dynamic extends BuiltInDataType {

	/**
	 * Compute the length for this data-type which corresponds to the 
	 * specified memory location.
	 * @param buf memory location
	 * @param maxLength maximum number of bytes to consume in computing length, or -1
	 * for unspecified.
	 * @return data length or -1 if it could not be determined.  Returned length may exceed
	 * maxLength if data-type does not supported constrained lengths.
	 */
	int getLength(MemBuffer buf, int maxLength);

	/**
	 * Returns true if a user-specified length can be used
	 */
	boolean canSpecifyLength();

	/**
	 * Returns a suitable replacement base data-type for pointers and arrays 
	 * when exporting to C code
	 * @return suitable base data-type for this Dynamic data-type
	 */
	DataType getReplacementBaseType();
}
