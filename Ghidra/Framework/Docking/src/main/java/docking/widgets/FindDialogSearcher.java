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
 * A simple interface for the {@link FindDialog} so that it can work for different search clients.
 */
public interface FindDialogSearcher {

	public CursorPosition getCursorPosition();

	public void setCursorPosition(CursorPosition position);

	public CursorPosition getStart();

	public CursorPosition getEnd();

	public void highlightSearchResults(SearchLocation location);

	public SearchLocation search(String text, CursorPosition cursorPosition, boolean searchForward,
			boolean useRegex);
}
