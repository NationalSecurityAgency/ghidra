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
package generic.algorithms;

/**
 * A reducing LCS that works on Strings.
 */
public class StringReducingLcs extends ReducingLcs<String, Character> {

	public StringReducingLcs(String x, String y) {
		super(x, y);
	}

	@Override
	protected String reduce(String input, int start, int end) {
		return input.substring(start, end);
	}

	@Override
	protected int lengthOf(String s) {
		return s.length();
	}

	@Override
	protected Character valueOf(String s, int offset) {
		return s.charAt(offset);
	}
}
