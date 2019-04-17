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
 * <li>{@link StringLayoutEnum#FIXED_LEN} (ie. fixed length, trailing nulls trimmed, interior nulls retained)
 * <li>{@link StringLayoutEnum#NULL_TERMINATED_UNBOUNDED} (ie. null terminated and ignores data instance length)
 * <li>{@link StringLayoutEnum#NULL_TERMINATED_BOUNDED} (ie. null-terminated and limited to data instance)
 * <li>{@link StringLayoutEnum#PASCAL_255} (ie. pascal string, using 1 byte for length field, max 255 char elements)
 * <li>{@link StringLayoutEnum#PASCAL_64k} (ie. pascal string, using 2 bytes for length field, max 64k char elements)
 * </ul>
 */
public enum StringLayoutEnum {
	FIXED_LEN("fixed length"),
	NULL_TERMINATED_UNBOUNDED("null-terminated & unbounded"),
	NULL_TERMINATED_BOUNDED("null-terminated & bounded"),
	PASCAL_255("pascal255"), // prefixed with 1 byte length field which stores number of chars (not bytes) in string
	PASCAL_64k("pascal64k");// prefixed with 2 byte length field which stores number of chars (not bytes) in string

	private final String s;

	private StringLayoutEnum(String s) {
		this.s = s;
	}

	@Override
	public String toString() {
		return s;
	}

	public boolean isPascal() {
		return this == PASCAL_255 || this == PASCAL_64k;
	}

	public boolean isNullTerminated() {
		return this == NULL_TERMINATED_UNBOUNDED ||
			this == StringLayoutEnum.NULL_TERMINATED_BOUNDED;
	}

}
