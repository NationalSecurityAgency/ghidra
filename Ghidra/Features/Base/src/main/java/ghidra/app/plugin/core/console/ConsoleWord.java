/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.console;

class ConsoleWord {
	public final String word;
	public final int startPosition;
	public final int endPosition;

	ConsoleWord(String word, int startPosition, int endPosition) {
		this.word = word;
		this.startPosition = startPosition;
		this.endPosition = endPosition;
	}

	ConsoleWord getWordWithoutSpecialCharacters() {
		StringBuilder buffy = new StringBuilder(word);

		// trim the back
		int newEndPosition = endPosition;
		while (buffy.length() > 0 && isSpecialChar(buffy.charAt(buffy.length() - 1))) {
			buffy.deleteCharAt(buffy.length() - 1);
			newEndPosition--;
		}

		// trim the front
		int newStartPosition = startPosition;
		while (buffy.length() > 0 && isSpecialChar(buffy.charAt(0))) {
			buffy.deleteCharAt(0);
			newStartPosition++;
		}

		return new ConsoleWord(buffy.toString(), newStartPosition, newEndPosition);
	}

	private boolean isSpecialChar(char c) {
		return c == ']' || c == '[' || c == ',' || c == '.';
	}

	@Override
	public String toString() {
		return word + "(" + startPosition + "," + endPosition + ")";
	}
}
