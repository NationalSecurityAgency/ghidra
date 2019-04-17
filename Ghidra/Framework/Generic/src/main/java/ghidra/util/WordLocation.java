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
package ghidra.util;

import org.apache.commons.lang3.StringUtils;

/**
 * A simple object that represents a word as defined by 
 * {@link StringUtilities#findWord(String, int)}.  This class contains the position of the word
 * within the original context from whence it came.
 */
public class WordLocation {

	private final String context;
	private final String word;
	private final int start;

	public static WordLocation empty(String context) {
		return new WordLocation(context, "", -1);
	}

	public WordLocation(String context, String word, int start) {
		this.context = context;
		this.word = word;
		this.start = start;
	}

	public boolean isEmpty() {
		return StringUtils.isBlank(word);
	}

	public String getContext() {
		return context;
	}

	public String getWord() {
		return word;
	}

	public int getStart() {
		return start;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tword: " + word + ",\n" +
			"\tstart: " + start + "\n" +
	    "}";
		//@formatter:on
	}
}
