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
package ghidra.util.bytesearch;

/**
 * Interface for Patterns that can be combined into a single state machine that can be 
 * simultaneously searched for in a byte sequence.
 */
public interface BytePattern {

	/**
	 * {@return the size of this pattern.}
	 */
	public int getSize();

	/**
	 * Checks if this pattern matches a byte value at a specific offset into the pattern.
	 * @param patternOffset the position in the pattern to check if it matches the given byte value
	 * @param byteValue the byte value to check if it matches the pattern at the given offset. This
	 * value is passed as an int so that the byte can be treated as unsigned. 
	 * @return true if this pattern matches the given byte value at the given pattern offset.
	 */
	public boolean isMatch(int patternOffset, int byteValue);

}
