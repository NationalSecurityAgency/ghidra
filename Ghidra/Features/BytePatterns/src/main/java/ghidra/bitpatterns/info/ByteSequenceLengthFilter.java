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
package ghidra.bitpatterns.info;

/**
 * 
 * Objects of this class are used to access prefixes or suffixes of {@code String}s, as well as filter 
 * {@code String}s by length.
 *  
 */
public class ByteSequenceLengthFilter {

	private int internalIndex;//if positive, the filter will return the first internalIndex characters
	//if negative, it will return the last internalIndex characters (think python string slicing)

	private int minLength;//the minimum length a string needs to be 

	/**
	 * @param internalIndex if positive, filter will return the first {@code internalIndex} 
	 * characters in the string.  Otherwise it will return the last {@code internalIndex} characters.
	 * @param minLength the minimum length of a string
	 * @throws IllegalArgumentException if {@code minLength} is negative or {@code minLength} < {@code internalIndex} 
	 */
	public ByteSequenceLengthFilter(int internalIndex, int minLength) {
		if (minLength < 0) {
			throw new IllegalArgumentException("minLength must be non-negative!");
		}

		if (minLength < Math.abs(internalIndex)) {
			throw new IllegalArgumentException("minLength too small for this internalIndex!");
		}
		//strings are hex digits, want to filter on the number of bytes
		this.internalIndex = 2 * internalIndex;
		this.minLength = 2 * minLength;
	}

	/**
	 * Applies filter to {@code base}
	 * @param base the String to filter
	 * @return The filtered {@link String}, or {@code null} if base does not meet the minimum length
	 * requirement.
	 */
	public String filter(String base) {
		if ((base == null) || (base.length() < minLength)) {
			return null;
		}
		if (internalIndex >= 0) {
			return base.substring(0, internalIndex);
		}
		int len = base.length();
		return base.substring(len + internalIndex, len);//internalIndex is negative

	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("internalIndex: ");
		sb.append(internalIndex);
		sb.append("\nminLength: ");
		sb.append(minLength);
		sb.append("\n");
		return sb.toString();
	}

}
