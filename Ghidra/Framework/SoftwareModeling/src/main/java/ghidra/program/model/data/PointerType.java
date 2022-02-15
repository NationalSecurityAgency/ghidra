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
package ghidra.program.model.data;

import java.util.NoSuchElementException;

import ghidra.program.database.data.PointerTypedefInspector;

/**
 * <code>PointerType</code> specified the pointer-type associated with a pointer-typedef.
 * @see PointerTypeSettingsDefinition
 * @see PointerTypedefBuilder
 * @see PointerTypedefInspector
 */
public enum PointerType {
	/**
	 * Normal absolute pointer offset
	 */
	DEFAULT(0),
	/**
	 * Pointer offset relative to program image base. 
	 */
	IMAGE_BASE_RELATIVE(1),
	/**
	 * Pointer offset relative to pointer storage address.
	 * NOTE: This type has limited usefulness since it can only be applied to
	 * a pointer stored in memory based upon its storage location.  Type-propogation
	 * should be avoided on the resulting pointer typedef.
	 */
	RELATIVE(2),
	/**
	 * Pointer offset corresponds to file offset within an associated file.
	 */
	FILE_OFFSET(3);

	final int value;

	PointerType(int value) {
		this.value = value;
	}

	/**
	 * Get the type associated with the specified value.
	 * @param val type value
	 * @return type
	 * @throws NoSuchElementException if invalid value specified
	 */
	public static PointerType valueOf(int val) throws NoSuchElementException {
		for (PointerType t : values()) {
			if (t.value == val) {
				return t;
			}
		}
		throw new NoSuchElementException("unknown type value: " + val);
	}
}
