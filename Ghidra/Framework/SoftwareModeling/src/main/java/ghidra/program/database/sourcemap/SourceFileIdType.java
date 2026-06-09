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
package ghidra.program.database.sourcemap;

import java.util.HashMap;
import java.util.Map;

/**
 * An enum whose values represent source file id types, such as md5 or sha1.
 */
public enum SourceFileIdType {
	NONE((byte) 0, 0),
	UNKNOWN((byte) 1, 0),
	TIMESTAMP_64((byte) 2, 8),
	MD5((byte) 3, 16),
	SHA1((byte) 4, 20),
	SHA256((byte) 5, 32),
	SHA512((byte) 6, 64);

	public static final int MAX_LENGTH = 64;
	private static Map<Byte, SourceFileIdType> valueToEnum;

	static {
		valueToEnum = new HashMap<>();
		for (SourceFileIdType type : SourceFileIdType.values()) {
			valueToEnum.put(type.getIndex(), type);
		}
	}

	private final int byteLength;
	private final byte index;

	private SourceFileIdType(byte index, int length) {
		byteLength = length;
		this.index = index;
	}

	/**
	 * Returns the byte length of the corresponding identifier. A value of 0 indicates
	 * no restriction.
	 * 
	 * @return byte length of identifier
	 */
	public int getByteLength() {
		return byteLength;
	}

	/**
	 * Returns the index of the identifier type.
	 * @return index
	 */
	byte getIndex() {
		return index;
	}

	/**
	 * Returns the id type given the index.
	 * @param index index
	 * @return id type
	 */
	static SourceFileIdType getTypeFromIndex(byte index) {
		return valueToEnum.get(index);

	}

}
