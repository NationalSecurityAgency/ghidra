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

/**
 * An object that describes a search result.
 */
public class SearchLocation {
	private final int startIndexInclusive;
	private final int endIndexInclusive;
	private final String searchText;
	private final boolean forwardDirection;

	public SearchLocation(int startIndexInclusive, int endIndexInclusive, String searchText,
			boolean forwardDirection) {

		this.startIndexInclusive = startIndexInclusive;
		this.endIndexInclusive = endIndexInclusive;
		this.searchText = searchText;
		this.forwardDirection = forwardDirection;
	}

	public CursorPosition getCursorPosition() {
		return new CursorPosition(startIndexInclusive);
	}

	public String getSearchText() {
		return searchText;
	}

	public int getEndIndexInclusive() {
		return endIndexInclusive;
	}

	public int getStartIndexInclusive() {
		return startIndexInclusive;
	}

	public int getMatchLength() {
		return endIndexInclusive - startIndexInclusive + 1;
	}

	public boolean isForwardDirection() {
		return forwardDirection;
	}

	@Override
	public String toString() {
		return searchText + "[" + fieldsToString() + "]";
	}

	protected String fieldsToString() {
		return startIndexInclusive + ", end=" + endIndexInclusive;
	}
}
