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

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Swift {@code ContextDescriptorKind} values
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h">swift/ABI/MetadataValues.h</a> 
 */
public enum ContextDescriptorKind implements StructConverter {
	
	/**
	 * This context descriptor represents a module
	 */
	Module(0),

	/**
	 * This context descriptor represents an extension
	 */
	Extension(1),

	/**
	 * This context descriptor represents an anonymous possibly-generic context such as a function
	 * body
	 */
	Anonymous(2),

	/**
	 * This context descriptor represents a protocol context
	 */
	Protocol(3),

	/**
	 * This context descriptor represents an opaque type alias
	 */
	OpaqueType(4),

	/**
	 * This context descriptor represents a class
	 */
	Class(16),

	/**
	 * This context descriptor represents a struct
	 */
	Struct(17),

	/**
	 * This context descriptor represents an enum
	 */
	Enum(18);

	private int value;

	/**
	 * Creates a new {@link ContextDescriptorKind}
	 * 
	 * @param value The kind value
	 */
	private ContextDescriptorKind(int value) {
		this.value = value;
	}

	/**
	 * {@return the kind value}
	 */
	public int getValue() {
		return value;
	}

	/**
	 * {@return the {@link ContextDescriptorKind} with the given kind value, or {@code null} if it 
	 * does not exist}
	 * 
	 * @param value The kind value to get the value of
	 */
	public static ContextDescriptorKind valueOf(int value) {
		return Arrays.stream(values()).filter(e -> e.getValue() == value).findFirst().orElse(null);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		EnumDataType dt = new EnumDataType(SwiftTypeMetadataStructure.CATEGORY_PATH,
			ContextDescriptorKind.class.getSimpleName(), 1);
		for (ContextDescriptorKind kind : values()) {
			dt.add(kind.name(), kind.getValue());
		}
		return dt;
	}
}
