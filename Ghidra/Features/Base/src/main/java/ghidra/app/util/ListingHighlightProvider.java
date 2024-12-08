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
package ghidra.app.util;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.program.model.listing.CodeUnit;

/**
 * Provider of Highlight objects appropriate {@link ListingField}s.
 */
public interface ListingHighlightProvider {

	public static final Highlight[] NO_HIGHLIGHTS = new Highlight[0];

	/**
	 * Get the highlights appropriate for the given text
	 * 
	 * @param text the entire text contained in the field, regardless of layout.
	 * @param field the field being rendered.  From this field you can get the field factory and 
	 *        the proxy object, which is usually a {@link CodeUnit}.
	 * @param cursorTextOffset the cursor position within the given text or -1 if no cursor in this 
	 *        field.
	 * @return an array of highlight objects that indicate the location within the text string to
	 *         be highlighted.
	 */
	public Highlight[] createHighlights(String text, ListingField field, int cursorTextOffset);
}
