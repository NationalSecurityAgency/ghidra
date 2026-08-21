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
package docking.widgets.search;

import docking.widgets.SearchLocation;

public class TextComponentSearchLocation extends SearchLocation {

	private boolean isActive;
	private Object lastHighlightTag;

	TextComponentSearchLocation(String searchText, int startInclusive, int endInclusive,
			int lineNumber, SearchLocationContext context) {
		super(startInclusive, endInclusive, searchText, lineNumber, context);
	}

	void setActive(boolean b) {
		isActive = b;
	}

	boolean isActive() {
		return isActive;
	}

	// sets the Highlighter created that allows for removal of the highlight for this match
	void setHighlightTag(Object tag) {
		this.lastHighlightTag = tag;
	}

	Object getHighlightTag() {
		return lastHighlightTag;
	}

}
