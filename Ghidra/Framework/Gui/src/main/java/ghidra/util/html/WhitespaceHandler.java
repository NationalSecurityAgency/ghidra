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
package ghidra.util.html;

/**
 * Simple interface to handle dealing with whitespace in strings when wrapping.
 */
interface WhitespaceHandler {

	/**
	 * Counts the number of contiguous spaces in the given string starting from the 
	 * given offset.
	 * 
	 * @param s the string
	 * @param offset the offset in the string at which to start
	 * @return the number of contiguous spaces
	 */
	public int countSpaces(String s, int offset);

	/**
	 * Trim the given string (or don't, it's up to the implementation).
	 * 
	 * @param s the string
	 * @return the trimmed string
	 */
	public String trim(String s);
}
