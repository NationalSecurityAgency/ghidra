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
package ghidra.app.plugin.core.strings;

import java.util.Iterator;

/**
 * Splits a string into trigrams
 */
public class StringTrigramIterator implements Iterator<Trigram> {
	private final String s;
	private int index = 0;
	private int prevCodePoints[] = new int[2];

	public StringTrigramIterator(String s) {
		// throw away string if length is less than 3
		this.s = s.codePointCount(0, s.length()) >= 3 ? s : null;
		if (hasNext()) {
			next(); // throw away first value which will be "\0, \0, first char"
		}
	}

	@Override
	public boolean hasNext() {
		return s != null && index <= s.length();
	}

	@Override
	public Trigram next() {
		int codePoint = index >= s.length() ? '\0' : s.codePointAt(index);
		index += Character.charCount(codePoint);

		Trigram result =
			new Trigram(new int[] { prevCodePoints[0], prevCodePoints[1], codePoint });
		prevCodePoints[0] = prevCodePoints[1];
		prevCodePoints[1] = codePoint;
		return result;
	}

}
