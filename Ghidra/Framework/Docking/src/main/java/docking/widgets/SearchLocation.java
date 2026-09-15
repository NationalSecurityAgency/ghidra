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
package docking.widgets;

import docking.widgets.search.SearchLocationContext;

/**
 * An object that describes a search result.
 */
public class SearchLocation {
	private final int startIndexInclusive;
	private final int endIndexInclusive;
	private final String text;
	private SearchLocationContext context;
	private int lineNumber;

	public SearchLocation(int startIndexInclusive, int endIndexInclusive, String text) {

		this.startIndexInclusive = startIndexInclusive;
		this.endIndexInclusive = endIndexInclusive;
		this.text = text;
	}

	public SearchLocation(int startIndexInclusive, int endIndexInclusive, String text,
			int lineNumber, SearchLocationContext context) {

		this.startIndexInclusive = startIndexInclusive;
		this.endIndexInclusive = endIndexInclusive;
		this.text = text;
		this.context = context;
		this.lineNumber = lineNumber;
	}

	public SearchLocationContext getContext() {
		return context;
	}

	public int getLineNumber() {
		return lineNumber;
	}

	public CursorPosition getCursorPosition() {
		return new CursorPosition(startIndexInclusive);
	}

	public int getEndIndexInclusive() {
		return endIndexInclusive;
	}

	public int getStartIndexInclusive() {
		return startIndexInclusive;
	}

	public boolean contains(int pos) {
		return startIndexInclusive <= pos && endIndexInclusive >= pos;
	}

	public int getMatchLength() {
		return endIndexInclusive - startIndexInclusive + 1;
	}

	@Override
	public String toString() {
		return text + "[" + fieldsToString() + "]";
	}

	protected String fieldsToString() {
		return "line=%s, start=%s, end=%s".formatted(lineNumber, startIndexInclusive,
			endIndexInclusive);
	}
}
