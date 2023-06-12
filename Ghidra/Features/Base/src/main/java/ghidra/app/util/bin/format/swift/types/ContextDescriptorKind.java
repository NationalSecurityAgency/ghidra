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
package ghidra.app.util.bin.format.swift.types;

/**
 * Swift ContextDescriptorKind values
 * 
 * @see <a href="https://github.com/apple/swift/blob/main/include/swift/ABI/MetadataValues.h">swift/ABI/MetadataValues.h</a> 
 */
public class ContextDescriptorKind {

	/**
	 * The mask to apply to the {@link TargetContextDescriptor#getFlags() flags} to get the
	 * {@link ContextDescriptorKind} value
	 */
	private static int KIND_MASK = 0x1f;

	/**
	 * Gets the {@link ContextDescriptorKind} value from the 
	 * {@link TargetContextDescriptor#getFlags() flags}
	 * 
	 * @param flags The {@link TargetContextDescriptor#getFlags() flags} that contain the kind
	 * @return The {@link ContextDescriptorKind} value
	 */
	public static int getKind(int flags) {
		return flags & KIND_MASK;
	}

	//---------------------------------------------------------------------------------------------

	/**
	 * This context descriptor represents a module
	 */
	public static final int MODULE = 0;

	/**
	 * This context descriptor represents an extension
	 */
	public static final int EXTENSION = 1;

	/**
	 * This context descriptor represents an anonymous possibly-generic context such as a function
	 * body
	 */
	public static final int ANONYMOUS = 2;

	/**
	 * This context descriptor represents a protocol context
	 */
	public static final int PROTOCOL = 3;

	/**
	 * This context descriptor represents an opaque type alias
	 */
	public static final int OPAQUE_TYPE = 4;

	/**
	 * First kind that represents a type of any sort
	 */
	public static final int TYPE_FIRST = 16;

	/**
	 * This context descriptor represents a class
	 */
	public static final int CLASS = TYPE_FIRST;

	/**
	 * This context descriptor represents a struct
	 */
	public static final int STRUCT = TYPE_FIRST + 1;

	/**
	 * This context descriptor represents an enum
	 */
	public static final int ENUM = TYPE_FIRST + 2;

	/**
	 * Last kind that represents a type of any sort
	 */
	public static final int TYPE_LAST = 31;
}
