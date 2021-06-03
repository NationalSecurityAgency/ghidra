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

/**
 * Controls strings termination
 * <ul>
 * <li>{@link StringLayoutEnum#FIXED_LEN}
 * <li>{@link StringLayoutEnum#CHAR_SEQ}
 * <li>{@link StringLayoutEnum#NULL_TERMINATED_UNBOUNDED}
 * <li>{@link StringLayoutEnum#NULL_TERMINATED_BOUNDED}
 * <li>{@link StringLayoutEnum#PASCAL_255}
 * <li>{@link StringLayoutEnum#PASCAL_64k}
 * </ul>
 */
public enum StringLayoutEnum {
	/**
	 * Fixed length string, trailing nulls trimmed, interior nulls retained.
	 */
	FIXED_LEN("fixed length"),
	/**
	 * Fixed length sequence of characters, all nulls retained.
	 */
	CHAR_SEQ("char sequence"),
	/**
	 * Null terminated string that ignores it's container's length when searching for terminating null character.
	 */
	NULL_TERMINATED_UNBOUNDED("null-terminated & unbounded"),
	/**
	 * Null-terminated string that is limited to it's container's length.
	 */
	NULL_TERMINATED_BOUNDED("null-terminated & bounded"),
	/**
	 * Pascal string, using 1 byte for length field, max 255 char elements.
	 */
	PASCAL_255("pascal255"),
	/**
	 * Pascal string, using 2 bytes for length field, max 64k char elements
	 */
	PASCAL_64k("pascal64k");

	private final String s;

	private StringLayoutEnum(String s) {
		this.s = s;
	}

	@Override
	public String toString() {
		return s;
	}

	/**
	 * Returns true if this layout is one of the pascal types.
	 * 
	 * @return boolean true if pascal
	 */
	public boolean isPascal() {
		return this == PASCAL_255 || this == PASCAL_64k;
	}

	/**
	 * Returns true if this layout is one of the null terminated types.
	 * 
	 * @return boolean true if null terminated string
	 */
	public boolean isNullTerminated() {
		return this == NULL_TERMINATED_UNBOUNDED ||
			this == NULL_TERMINATED_BOUNDED;
	}

	/**
	 * Returns true if this layout should have its trailing null characters trimmed.
	 * 
	 * @return boolean true if trailing nulls should be trimmed
	 */
	public boolean shouldTrimTrailingNulls() {
		return this == NULL_TERMINATED_UNBOUNDED || this == NULL_TERMINATED_BOUNDED ||
			this == FIXED_LEN;
	}

	/**
	 * Returns true if this layout is one of the fixed-size types.
	 * 
	 * @return boolean true if fixed length
	 */
	public boolean isFixedLen() {
		return this == FIXED_LEN || this == CHAR_SEQ;
	}

}
