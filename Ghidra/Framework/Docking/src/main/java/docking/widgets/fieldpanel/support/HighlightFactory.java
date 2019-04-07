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
package docking.widgets.fieldpanel.support;

import docking.widgets.fieldpanel.field.Field;

public interface HighlightFactory {

	/**
	 * Returns the highlights for the given text
	 *
	 * @param field the field that is requesting the highlight
	 * @param text the text to be considered for highlighting
	 * @param cursorTextOffset the position in the given text of the cursor. A -1 indicates the
	 * 		  cursor is not in this field.
	 * @return an array of highlights to be rendered
	 */
	public Highlight[] getHighlights(Field field, String text, int cursorTextOffset);
}
