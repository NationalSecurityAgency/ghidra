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
import java.util.*;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * Swift {@code InvertibleProtocolKind} values
 * 
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/InvertibleProtocols.h">swift/ABI/InvertibleProtocols.h</a>
 * @see <a href="https://github.com/swiftlang/swift/blob/main/include/swift/ABI/InvertibleProtocols.def">swift/ABI/InvertibleProtocols.def</a>  
 */
public enum InvertibleProtocolKind implements StructConverter {

	Copyable(0),
	Escapable(1);

	private int bit;

	/**
	 * Creates a new {@link InvertibleProtocolKind}
	 * 
	 * @param bit The bit number that represents the kind
	 */
	private InvertibleProtocolKind(int bit) {
		this.bit = bit;
	}

	/**
	 * {@return the bit number that represents the kind}
	 */
	public int getBit() {
		return bit;
	}

	/**
	 * {@return the {@link Set} of {@link InvertibleProtocolKind}s that map to the given kind value}
	 * 
	 * @param value The kind value to get the value of
	 */
	public static Set<InvertibleProtocolKind> valueOf(short value) {
		Set<InvertibleProtocolKind> set = new HashSet<>();
		for (int i = 0; i < 16; i++) {
			final int bitPos = i;
			int bit = (value >> bitPos) & 0x1;
			if (bit != 0) {
				Arrays.stream(values())
						.filter(e -> e.getBit() == bitPos)
						.findFirst()
						.ifPresent(set::add);
			}
		}
		return set;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		EnumDataType dt = new EnumDataType(SwiftTypeMetadataStructure.CATEGORY_PATH,
			InvertibleProtocolKind.class.getSimpleName(), 2);
		for (InvertibleProtocolKind kind : values()) {
			dt.add(kind.name(), 1 << kind.getBit());
		}
		return dt;
	}
}
